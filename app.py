import base64, hashlib, hmac, secrets
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

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def hash_pw(password, salt=None):
    salt = bytes.fromhex(salt) if salt else secrets.token_bytes(16)
    return salt.hex(), hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS).hex()
def verify_pw(password, salt, expected):
    try: return hmac.compare_digest(hash_pw(password, salt)[1], expected)
    except (ValueError, TypeError): return False

try:
    sb = create_client(st.secrets["supabase"]["url"].strip(), st.secrets["supabase"]["service_role_key"].strip())
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
            sb.table("app_users").insert({"username": username, "display_name": display, "role": role,
                "salt_hex": salt, "password_hash": digest, "active": True, "created_at": now()}).execute()
except Exception as e:
    st.error(f"Could not initialize accounts. Check that schema.sql was run successfully. Details: {e}")
    st.stop()

if "auth_user" not in st.session_state: st.session_state.auth_user = None
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
                st.session_state.auth_user = {"username": u["username"], "display_name": u["display_name"], "role": u["role"]}
                st.rerun()
            else: st.error("Invalid username or password, or account inactive.")
        except Exception: st.error("Login failed. Check the database connection.")
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
    q = sb.table("audit_batches").select("audit_id,submitted_at,submitted_by,original_filename,status,item_count,matched_count,pending_count,approved_count,rejected_count").order("submitted_at", desc=True).execute()
    rows = q.data or []
    return rows if me["role"] == "Manager" else [r for r in rows if r["submitted_by"] == me["username"]]
def items(audit_id=None):
    q = sb.table("audit_items").select("*")
    if audit_id: q = q.eq("audit_id", audit_id)
    return q.order("created_at", desc=True).execute().data or []

if page == "Upload Audit":
    if me["role"] != "Clerk": st.error("Access denied."); st.stop()
    st.header("Clerk Dashboard — Upload Stock Audit Sheet")
    st.info("Required columns: SKU and Physical_Count. Common aliases such as SKU/Code and audited_quantity are also accepted.")
    template = pd.DataFrame([{"SKU":"SKU-1001","Physical_Count":145},{"SKU":"SKU-1002","Physical_Count":12}])
    st.download_button("Download CSV Template", template.to_csv(index=False).encode(), "stock_audit_template.csv", "text/csv")
    f = st.file_uploader("Upload CSV or Excel file", type=["csv","xlsx"])
    if f:
        try:
            raw = f.getvalue()
            if len(raw) > MAX_BYTES: raise ValueError("File exceeds the 10 MB limit.")
            df = pd.read_csv(BytesIO(raw)) if f.name.lower().endswith(".csv") else pd.read_excel(BytesIO(raw), engine="openpyxl")
            original_cols = list(df.columns)
            mapping = {}
            aliases = {"sku":["sku","sku/code","sku_code","item_code","stock_keeping_unit_id"],
                       "physical_count":["physical_count","physical count","physical_qty","audited_quantity","physical_quantity","actual_count"]}
            normalized = {str(c).strip().lower(): c for c in original_cols}
            for target, names in aliases.items():
                for name in names:
                    if name in normalized: mapping[normalized[name]] = target; break
            df = df.rename(columns=mapping)
            if not {"sku","physical_count"}.issubset(df.columns):
                raise ValueError("Missing columns. Required: SKU and Physical_Count.")
            df = df[["sku","physical_count"]].copy()
            df["sku"] = df["sku"].astype("string").str.strip()
            df["physical_count"] = pd.to_numeric(df["physical_count"], errors="coerce")
            if df.empty: raise ValueError("The file has no data rows.")
            if df["sku"].isna().any() or (df["sku"] == "").any(): raise ValueError("Every row needs a SKU.")
            if df["sku"].duplicated().any(): raise ValueError("Duplicate SKUs are not allowed.")
            if df["physical_count"].isna().any() or (df["physical_count"] < 0).any() or ((df["physical_count"] % 1) != 0).any():
                raise ValueError("Physical_Count must be a non-negative whole number on every row.")
            df["sku"] = df["sku"].astype(str); df["physical_count"] = df["physical_count"].astype(int)
            st.subheader("Uploaded file preview"); st.dataframe(df, use_container_width=True, hide_index=True)
            inv = inventory()
            imap = {x["sku"]: x for x in inv}
            unknown = sorted(set(df["sku"]) - set(imap))
            if unknown: st.error("Unknown SKU(s): " + ", ".join(unknown))
            else:
                preview = []
                for row in df.to_dict("records"):
                    x = imap[row["sku"]]; variance = int(row["physical_count"]) - int(x["system_qty"])
                    preview.append({"sku": row["sku"], "item_name": x["item_name"], "system_qty": int(x["system_qty"]),
                        "physical_qty": int(row["physical_count"]), "variance_qty": variance,
                        "variance_value": round(variance * float(x["unit_cost"]), 2),
                        "status": "Matched" if variance == 0 else "Pending Approval"})
                st.subheader("Reconciliation preview"); st.dataframe(pd.DataFrame(preview), use_container_width=True, hide_index=True)
                st.warning("Uploading does not change inventory. Only an authorized manager can approve an adjustment.")
                if st.button("Submit Audit Batch", type="primary"):
                    audit_id = "AUD-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3).upper()
                    payload = [{"sku":r["sku"],"item_name":r["item_name"],"system_qty":r["system_qty"],
                        "physical_qty":r["physical_qty"],"variance_qty":r["variance_qty"],
                        "variance_value":r["variance_value"],"status":r["status"]} for r in preview]
                    sb.rpc("submit_audit_batch", {"p_audit_id":audit_id,"p_submitted_by":me["username"],
                        "p_original_filename":f.name,"p_original_file_base64":base64.b64encode(raw).decode(),
                        "p_items":payload}).execute()
                    st.success(f"Saved audit batch {audit_id} to the database.")
                    st.rerun()
        except Exception as e: st.error(f"Could not process or save file: {e}")

elif page == "Manager Review":
    if me["role"] != "Manager": st.error("Access denied."); st.stop()
    st.header("Manager Dashboard — Discrepancy Review & Write-Off Authorization")
    pending = [r for r in items() if r["status"] == "Pending Approval"]
    if not pending: st.success("No pending discrepancies require authorization.")
    for r in pending:
        with st.expander(f"{r['audit_id']} | {r['sku']} — {r['item_name']} | Variance {int(r['variance_qty']):+d}", expanded=True):
            a,b,c,d = st.columns(4)
            a.metric("System Qty", r["system_qty"]); b.metric("Physical Qty", r["physical_qty"])
            c.metric("Variance", f"{r['variance_qty']:+d}"); d.metric("Variance Value", f"{float(r['variance_value']):,.2f}")
            note = st.text_area("Manager note (required)", key=f"note_{r['id']}", max_chars=1000)
            left,right = st.columns(2)
            if left.button("Authorize Write-Off / Adjust Inventory", key=f"approve_{r['id']}", type="primary"):
                if not note.strip(): st.error("Enter a note before approving.")
                else:
                    try:
                        sb.rpc("review_audit_item", {"p_item_id":r["id"],"p_manager_username":me["username"],
                            "p_decision":"approve","p_manager_notes":note.strip()}).execute()
                        st.success("Approved. Inventory adjusted and decision recorded."); st.rerun()
                    except Exception as e: st.error(f"Approval failed: {e}")
            if right.button("Reject Discrepancy", key=f"reject_{r['id']}"):
                if not note.strip(): st.error("Enter a note before rejecting.")
                else:
                    try:
                        sb.rpc("review_audit_item", {"p_item_id":r["id"],"p_manager_username":me["username"],
                            "p_decision":"reject","p_manager_notes":note.strip()}).execute()
                        st.info("Rejected. Inventory was not changed."); st.rerun()
                    except Exception as e: st.error(f"Rejection failed: {e}")

elif page == "Audit History":
    st.header("Audit History — Previously Uploaded Sheets")
    st.caption("Managers see all batches; clerks see only batches they submitted.")
    try:
        bs = batches()
        if not bs: st.info("No saved audit batches.")
        else:
            st.dataframe(pd.DataFrame(bs), use_container_width=True, hide_index=True)
            options = {f"{b['audit_id']} — {b['original_filename']} — {b['submitted_at']}":b["audit_id"] for b in bs}
            label = st.selectbox("Choose a batch", list(options))
            aid = options[label]
            batch = sb.table("audit_batches").select("*").eq("audit_id",aid).single().execute().data
            if batch and batch.get("original_file_base64"):
                st.download_button("Download Original Audit Sheet", base64.b64decode(batch["original_file_base64"]),
                    batch["original_filename"], "application/octet-stream")
            rows = items(aid)
            if rows: st.subheader("Audit items"); st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    except Exception as e: st.error(f"Could not load audit history: {e}")

elif page == "Inventory":
    st.header("Master Inventory")
    try:
        inv = pd.DataFrame(inventory())
        if inv.empty: st.info("Inventory is empty.")
        else:
            inv["total_stock_value"] = inv["system_qty"] * inv["unit_cost"]
            a,b,c = st.columns(3); a.metric("SKU Count",len(inv)); b.metric("Units in Stock",f"{int(inv['system_qty'].sum()):,}")
            c.metric("Inventory Value",f"{inv['total_stock_value'].sum():,.2f}")
            st.dataframe(inv, use_container_width=True, hide_index=True)
            st.download_button("Export Inventory CSV", inv.to_csv(index=False).encode(), "master_inventory.csv", "text/csv")
    except Exception as e: st.error(f"Could not load inventory: {e}")

st.sidebar.divider()
st.sidebar.caption("Submitted audits and decisions are stored in Supabase, not only in browser session state.")
