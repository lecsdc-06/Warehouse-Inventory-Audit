import base64, hashlib, hmac, secrets, re, unicodedata
from datetime import datetime, timezone
from io import BytesIO

import pandas as pd
import streamlit as st
from supabase import create_client

st.set_page_config(page_title="Warehouse Inventory Audit & Discrepancy Manager", page_icon="📦", layout="wide")
st.title("Warehouse Inventory Audit & Discrepancy Manager")
st.caption("SDF04 — Clerk Audit Submission • Manager Review • Persistent Audit History")

MAX_BYTES = 10 * 1024 * 1024
ITERATIONS = 310_000


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hash_pw(password, salt=None):
    salt = bytes.fromhex(salt) if salt else secrets.token_bytes(16)
    return salt.hex(), hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS).hex()


def verify_pw(password, salt, expected):
    try:
        return hmac.compare_digest(hash_pw(password, salt)[1], expected)
    except (ValueError, TypeError):
        return False


def normalize_header(value):
    """Normalize Excel/CSV headers without changing the displayed source file."""
    text = unicodedata.normalize("NFKC", str(value)).replace("\ufeff", "").strip().lower()
    text = re.sub(r"[\s\-_\/]+", "_", text)
    return text.strip("_")


def normalize_sku(value):
    """Normalize common Excel SKU formatting while retaining the master SKU in storage."""
    if pd.isna(value):
        return ""
    text = unicodedata.normalize("NFKC", str(value)).replace("\ufeff", "").strip()
    # Excel sometimes turns SKU-like numeric/text values into a float-looking string.
    if re.fullmatch(r"(?i)sku-\d+\.0", text):
        text = text[:-2]
    return text.upper()


def parse_physical_count(series):
    # Keep Excel values as numeric quantities; reject text that is not a whole number.
    numeric = pd.to_numeric(series, errors="coerce")
    return numeric


try:
    sb = create_client(
        st.secrets["supabase"]["url"].strip(),
        st.secrets["supabase"]["service_role_key"].strip(),
    )
    configured = [
        ("clerk", st.secrets["auth"]["clerk_display_name"], "Clerk", st.secrets["auth"]["clerk_password"]),
        ("manager", st.secrets["auth"]["manager_display_name"], "Manager", st.secrets["auth"]["manager_password"]),
    ]
except Exception:
    st.error("Configuration missing. Follow README.md to run schema.sql in Supabase and add Streamlit Secrets.")
    st.stop()


def user_row(username):
    r = sb.table("app_users").select("*").eq("username", username.lower().strip()).limit(1).execute()
    return r.data[0] if r.data else None


try:
    for username, display, role, password in configured:
        if len(password) < 12:
            st.error(f"Password for {username} must be at least 12 characters in Streamlit Secrets.")
            st.stop()
        if not user_row(username):
            salt, digest = hash_pw(password)
            sb.table("app_users").insert({
                "username": username,
                "display_name": display,
                "role": role,
                "salt_hex": salt,
                "password_hash": digest,
                "active": True,
                "created_at": now(),
            }).execute()
except Exception as e:
    st.error(f"Could not initialize accounts. Check that schema.sql was run successfully. Details: {e}")
    st.stop()


if "auth_user" not in st.session_state:
    st.session_state.auth_user = None

if st.session_state.auth_user is None:
    st.subheader("Log in")
    with st.form("login"):
        username = st.text_input("Username").strip().lower()
        password = st.text_input("Password", type="password")
        go = st.form_submit_button("Log in", type="primary")
    if go:
        try:
            u = user_row(username)
            if u and u["active"] and verify_pw(password, u["salt_hex"], u["password_hash"]):
                st.session_state.auth_user = {
                    "username": u["username"],
                    "display_name": u["display_name"],
                    "role": u["role"],
                }
                st.rerun()
            else:
                st.error("Invalid username or password, or account inactive.")
        except Exception:
            st.error("Login failed. Check the database connection.")
    st.stop()


me = st.session_state.auth_user
st.sidebar.success(f"{me['display_name']} ({me['role']})")

if st.sidebar.button("Log out"):
    st.session_state.auth_user = None
    st.rerun()

if me["role"] == "Clerk":
    page = st.sidebar.radio("Navigation", ["Upload Audit", "Audit History", "Inventory"])
else:
    page = st.sidebar.radio("Navigation", ["Manager Review", "Audit History", "Inventory"])


def inventory():
    return sb.table("inventory").select("*").order("sku").execute().data or []


def batches():
    q = (
        sb.table("audit_batches")
        .select(
            "audit_id,submitted_at,submitted_by,original_filename,status,"
            "item_count,matched_count,pending_count,approved_count,rejected_count"
        )
        .order("submitted_at", desc=True)
        .execute()
    )
    rows = q.data or []
    return rows if me["role"] == "Manager" else [r for r in rows if r["submitted_by"] == me["username"]]


def items(audit_id=None):
    q = sb.table("audit_items").select("*")
    if audit_id:
        q = q.eq("audit_id", audit_id)
    return q.order("created_at", desc=False).execute().data or []


def load_uploaded_file(f):
    raw = f.getvalue()
    if len(raw) > MAX_BYTES:
        raise ValueError("File exceeds the 10 MB limit.")

    if f.name.lower().endswith(".csv"):
        df = pd.read_csv(BytesIO(raw), dtype=object)
    else:
        df = pd.read_excel(BytesIO(raw), engine="openpyxl", dtype=object)

    if df.empty:
        raise ValueError("The file has no data rows.")

    # Normalize headers, but keep the original file untouched for download/history.
    header_map = {}
    aliases = {
        "sku": {
            "sku", "sku_code", "sku_code_id", "sku_code_number",
            "sku_code_item", "sku_item_code", "sku_code_value",
            "sku/code", "item_code", "stock_keeping_unit_id",
        },
        "physical_count": {
            "physical_count", "physical_count_qty", "physical_count_quantity",
            "physical_qty", "physical_quantity", "audited_quantity",
            "actual_count", "actual_quantity", "counted_quantity",
        },
        "uploaded_item_name": {
            "item_name", "item", "product_name", "description",
            "item_description", "product_description",
        },
    }

    normalized_headers = {}
    for original in df.columns:
        normalized_headers[normalize_header(original)] = original

    for target, accepted in aliases.items():
        found = None
        for alias in accepted:
            key = normalize_header(alias)
            if key in normalized_headers:
                found = normalized_headers[key]
                break
        if found is not None:
            header_map[found] = target

    df = df.rename(columns=header_map)

    if "sku" not in df.columns or "physical_count" not in df.columns:
        raise ValueError(
            "Missing required columns. The file must contain SKU and Physical_Count "
            "(aliases such as SKU/Code and audited_quantity are accepted)."
        )

    keep = ["sku", "physical_count"]
    optional_columns = [
        "uploaded_item_name",
        "uploaded_system_count",
        "uploaded_category",
        "uploaded_location",
        "uploaded_unit_cost",
        "uploaded_notes",
    ]
    for col in optional_columns:
        if col in df.columns:
            keep.append(col)
    df = df[keep].copy()

    # Remove completely blank rows. A blank row in an Excel sheet should not become an audit item.
    df = df.dropna(how="all").reset_index(drop=True)
    if df.empty:
        raise ValueError("The file has no data rows.")

    df["source_row"] = df.index + 2  # Excel/CSV header is row 1.
    df["sku_original"] = df["sku"]
    df["sku"] = df["sku"].map(normalize_sku)

    if "uploaded_item_name" not in df.columns:
        df["uploaded_item_name"] = ""
    df["uploaded_item_name"] = df["uploaded_item_name"].fillna("").astype(str).str.strip()

    if "uploaded_system_count" in df.columns:
        df["uploaded_system_count"] = pd.to_numeric(
            df["uploaded_system_count"], errors="coerce"
        )
        if (
            df["uploaded_system_count"].isna().any()
            or (df["uploaded_system_count"] < 0).any()
            or ((df["uploaded_system_count"] % 1) != 0).any()
        ):
            bad_rows = df.loc[
                df["uploaded_system_count"].isna()
                | (df["uploaded_system_count"] < 0)
                | ((df["uploaded_system_count"] % 1) != 0),
                "source_row",
            ].tolist()
            raise ValueError(
                "System_Count must be a non-negative whole number when supplied. "
                f"Check source row(s): {bad_rows}"
            )
        df["uploaded_system_count"] = df["uploaded_system_count"].astype(int)

    for col in ["uploaded_category", "uploaded_location", "uploaded_notes"]:
        if col not in df.columns:
            df[col] = ""
        df[col] = df[col].fillna("").astype(str).str.strip()

    if "uploaded_unit_cost" in df.columns:
        df["uploaded_unit_cost"] = pd.to_numeric(df["uploaded_unit_cost"], errors="coerce")
        if df["uploaded_unit_cost"].isna().any() or (df["uploaded_unit_cost"] < 0).any():
            bad_rows = df.loc[
                df["uploaded_unit_cost"].isna() | (df["uploaded_unit_cost"] < 0),
                "source_row",
            ].tolist()
            raise ValueError(
                "Unit Cost must be a non-negative number when supplied. "
                f"Check source row(s): {bad_rows}"
            )


    if (df["sku"] == "").any():
        bad_rows = df.loc[df["sku"] == "", "source_row"].tolist()
        raise ValueError(f"Every data row needs a SKU. Blank SKU row(s): {bad_rows}")

    if df["sku"].duplicated().any():
        dupes = sorted(df.loc[df["sku"].duplicated(keep=False), "sku"].unique().tolist())
        raise ValueError("Duplicate SKUs are not allowed: " + ", ".join(dupes))

    df["physical_count"] = parse_physical_count(df["physical_count"])
    if (
        df["physical_count"].isna().any()
        or (df["physical_count"] < 0).any()
        or ((df["physical_count"] % 1) != 0).any()
    ):
        bad_rows = df.loc[
            df["physical_count"].isna()
            | (df["physical_count"] < 0)
            | ((df["physical_count"] % 1) != 0),
            "source_row",
        ].tolist()
        raise ValueError(
            "Physical_Count must be a non-negative whole number on every row. "
            f"Check source row(s): {bad_rows}"
        )

    df["physical_count"] = df["physical_count"].astype(int)
    return raw, df


if page == "Upload Audit":
    if me["role"] != "Clerk":
        st.error("Access denied.")
        st.stop()

    st.header("Clerk Dashboard — Upload Stock Audit Sheet")
    st.info(
        "Required columns: SKU and Physical_Count. This importer also recognizes "
        "Item Name, System_Count, Category, Location, Unit Cost, and Notes. "
        "If System_Count is present, it must match Master Inventory before submission."
    )

    template = pd.DataFrame([
        {
            "SKU": "SKU-1001",
            "Item Name": "Example Item",
            "Category": "Electronics",
            "Location": "Shelf A1",
            "System_Count": 120,
            "Physical_Count": 118,
            "Unit Cost": 941.00,
            "Notes": "",
        },
    ])
    st.download_button(
        "Download CSV Template",
        template.to_csv(index=False).encode(),
        "stock_audit_template.csv",
        "text/csv",
    )

    f = st.file_uploader("Upload CSV or Excel file", type=["csv", "xlsx"])

    if f:
        try:
            raw, df = load_uploaded_file(f)

            inv = inventory()
            imap = {normalize_sku(x["sku"]): x for x in inv}

            unknown = sorted(set(df["sku"]) - set(imap))
            if unknown:
                st.error(
                    "Unknown SKU(s) in the uploaded file: "
                    + ", ".join(unknown)
                    + ". These rows cannot be submitted until the SKU matches the master inventory."
                )
                st.dataframe(
                    df[[
                        "source_row", "sku_original", "sku",
                        "physical_count", "uploaded_item_name",
                    ]],
                    use_container_width=True,
                    hide_index=True,
                )
                st.stop()

            st.subheader("Uploaded file preview")
            st.dataframe(
                df[[
                    "source_row", "sku_original", "sku",
                    "physical_count", "uploaded_item_name",
                ]],
                use_container_width=True,
                hide_index=True,
            )

            preview = []
            master_mismatches = []

            for row in df.to_dict("records"):
                x = imap[row["sku"]]
                system_qty = int(x["system_qty"])
                physical_qty = int(row["physical_count"])
                variance = physical_qty - system_qty
                uploaded_name = row.get("uploaded_item_name", "")
                master_name = x["item_name"]

                uploaded_system = row.get("uploaded_system_count", None)
                if uploaded_system is not None and not pd.isna(uploaded_system):
                    uploaded_system = int(uploaded_system)
                    if uploaded_system != system_qty:
                        master_mismatches.append({
                            "source_row": int(row["source_row"]),
                            "sku": x["sku"],
                            "uploaded_system_count": uploaded_system,
                            "master_system_qty": system_qty,
                        })

                preview.append({
                    "source_row": int(row["source_row"]),
                    "sku": x["sku"],
                    "uploaded_item_name": uploaded_name,
                    "master_item_name": master_name,
                    "system_qty_at_submission": system_qty,
                    "physical_qty": physical_qty,
                    "variance_qty": variance,
                    "variance_value": round(variance * float(x["unit_cost"]), 2),
                    "status": "Matched" if variance == 0 else "Pending Approval",
                })

            preview_df = pd.DataFrame(preview)

            if master_mismatches:
                st.error(
                    "The uploaded System_Count does not match the current Master Inventory. "
                    "Submission is blocked so the system cannot silently audit against the wrong baseline."
                )
                st.dataframe(
                    pd.DataFrame(master_mismatches),
                    use_container_width=True,
                    hide_index=True,
                )
                st.info(
                    "Update the Master Inventory first, then re-upload the audit. "
                    "For your supplied workbook, this is the reason the dashboard can show different item names and quantities."
                )

            st.subheader("Reconciliation preview")
            st.dataframe(preview_df, use_container_width=True, hide_index=True)

            name_mismatches = preview_df[
                (preview_df["uploaded_item_name"].str.strip() != "")
                & (preview_df["uploaded_item_name"].str.casefold()
                   != preview_df["master_item_name"].str.casefold())
            ]
            if not name_mismatches.empty:
                st.warning(
                    "Some uploaded item names do not match the master inventory name. "
                    "The SKU remains the authoritative identifier; the uploaded name is preserved for audit review."
                )

            st.warning(
                "Uploading does not change inventory. Only an authorized manager can approve an adjustment."
            )

            if st.button(
                "Submit Audit Batch",
                type="primary",
                disabled=bool(master_mismatches),
            ):
                audit_id = (
                    "AUD-"
                    + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
                    + "-"
                    + secrets.token_hex(3).upper()
                )

                payload = []
                for r in preview:
                    payload.append({
                        "source_row": r["source_row"],
                        "sku": r["sku"],
                        "uploaded_item_name": r["uploaded_item_name"],
                        "physical_qty": r["physical_qty"],
                    })

                result = sb.rpc(
                    "submit_audit_batch",
                    {
                        "p_audit_id": audit_id,
                        "p_submitted_by": me["username"],
                        "p_original_filename": f.name,
                        "p_original_file_base64": base64.b64encode(raw).decode(),
                        "p_items": payload,
                    },
                ).execute()

                if result:
                    st.success(f"Saved audit batch {audit_id} to the database.")
                    st.rerun()

        except Exception as e:
            st.error(f"Could not process or save file: {e}")


elif page == "Manager Review":
    if me["role"] != "Manager":
        st.error("Access denied.")
        st.stop()

    st.header("Manager Dashboard — Discrepancy Review & Write-Off Authorization")

    all_pending = [r for r in items() if r["status"] == "Pending Approval"]
    batch_map = {b["audit_id"]: b["original_filename"] for b in batches()}

    if not all_pending:
        st.success("No pending discrepancies require authorization.")

    for r in all_pending:
        uploaded_name = r.get("uploaded_item_name") or "(not supplied)"
        display_name = r.get("uploaded_item_name") or r.get("item_name") or r["sku"]
        with st.expander(
            f"{r['audit_id']} | {r['sku']} — {display_name} | "
            f"Variance {int(r['variance_qty']):+d}",
            expanded=True,
        ):
            st.caption(
                f"Uploaded file: {batch_map.get(r['audit_id'], 'unknown')} • "
                f"Source row: {r.get('source_row', '—')} • "
                f"Uploaded item name: {uploaded_name}"
            )

            a, b, c, d = st.columns(4)
            a.metric("System Qty at Upload", r["system_qty"])
            b.metric("Physical Qty in File", r["physical_qty"])
            c.metric("Variance", f"{int(r['variance_qty']):+d}")
            d.metric("Variance Value", f"{float(r['variance_value']):,.2f}")

            note = st.text_area(
                "Manager note (required)",
                key=f"note_{r['id']}",
                max_chars=1000,
            )
            left, right = st.columns(2)

            if left.button(
                "Authorize Write-Off / Adjust Inventory",
                key=f"approve_{r['id']}",
                type="primary",
            ):
                if not note.strip():
                    st.error("Enter a note before approving.")
                else:
                    try:
                        sb.rpc(
                            "review_audit_item",
                            {
                                "p_item_id": r["id"],
                                "p_manager_username": me["username"],
                                "p_decision": "approve",
                                "p_manager_notes": note.strip(),
                            },
                        ).execute()
                        st.success("Approved. Inventory adjusted and decision recorded.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Approval failed: {e}")

            if right.button("Reject Discrepancy", key=f"reject_{r['id']}"):
                if not note.strip():
                    st.error("Enter a note before rejecting.")
                else:
                    try:
                        sb.rpc(
                            "review_audit_item",
                            {
                                "p_item_id": r["id"],
                                "p_manager_username": me["username"],
                                "p_decision": "reject",
                                "p_manager_notes": note.strip(),
                            },
                        ).execute()
                        st.info("Rejected. Inventory was not changed.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Rejection failed: {e}")


elif page == "Audit History":
    st.header("Audit History — Previously Uploaded Sheets")
    st.caption("Managers see all batches; clerks see only batches they submitted.")

    try:
        bs = batches()
        if not bs:
            st.info("No saved audit batches.")
        else:
            st.dataframe(pd.DataFrame(bs), use_container_width=True, hide_index=True)

            options = {
                f"{b['audit_id']} — {b['original_filename']} — {b['submitted_at']}": b["audit_id"]
                for b in bs
            }
            label = st.selectbox("Choose a batch", list(options))
            aid = options[label]

            batch = (
                sb.table("audit_batches")
                .select("*")
                .eq("audit_id", aid)
                .single()
                .execute()
                .data
            )

            if batch and batch.get("original_file_base64"):
                st.download_button(
                    "Download Original Audit Sheet",
                    base64.b64decode(batch["original_file_base64"]),
                    batch["original_filename"],
                    "application/octet-stream",
                )

            rows = items(aid)
            if rows:
                st.subheader("Processed audit items — exact uploaded rows")
                history_df = pd.DataFrame(rows)
                wanted = [
                    "source_row", "sku", "uploaded_item_name", "item_name",
                    "system_qty", "physical_qty", "variance_qty",
                    "variance_value", "status", "manager_notes",
                    "reviewed_by", "reviewed_at",
                ]
                st.dataframe(
                    history_df[[c for c in wanted if c in history_df.columns]],
                    use_container_width=True,
                    hide_index=True,
                )
    except Exception as e:
        st.error(f"Could not load audit history: {e}")


elif page == "Inventory":
    st.header("Master Inventory")

    try:
        inv = pd.DataFrame(inventory())
        if inv.empty:
            st.info("Inventory is empty.")
        else:
            inv["total_stock_value"] = inv["system_qty"] * inv["unit_cost"]
            a, b, c = st.columns(3)
            a.metric("SKU Count", len(inv))
            b.metric("Units in Stock", f"{int(inv['system_qty'].sum()):,}")
            c.metric("Inventory Value", f"{inv['total_stock_value'].sum():,.2f}")
            st.dataframe(inv, use_container_width=True, hide_index=True)
            st.download_button(
                "Export Inventory CSV",
                inv.to_csv(index=False).encode(),
                "master_inventory.csv",
                "text/csv",
            )
    except Exception as e:
        st.error(f"Could not load inventory: {e}")


st.sidebar.divider()
st.sidebar.caption(
    "Submitted audits and decisions are stored in Supabase, not only in browser session state."
)
