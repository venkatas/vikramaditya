from pathlib import Path

import source_audit


def test_source_audit_redacts_hardcoded_config_secrets(tmp_path: Path):
    src = tmp_path / "app"
    src.mkdir()
    (src / "Web.config").write_text(
        '<configuration><connectionStrings>'
        '<add name="db" connectionString="Server=db;User ID=dummy_user;Password=PLACEHOLDER_DB_SECRET;" />'
        "</connectionStrings></configuration>"
    )

    findings = source_audit.scan_source_tree(src)

    secret_findings = [f for f in findings if f.rule_id == "source.hardcoded_secret"]
    assert secret_findings
    assert "PLACEHOLDER_DB_SECRET" not in secret_findings[0].evidence
    assert "<redacted>" in secret_findings[0].evidence


def test_source_audit_flags_base64_query_sensitive_flow(tmp_path: Path):
    src = tmp_path / "app"
    src.mkdir()
    (src / "ClientMailUpload.aspx.cs").write_text(
        """
        public partial class ClientMailUpload : System.Web.UI.Page {
          protected void Page_Load(object sender, EventArgs e) {
            var id = DecryptString(Request.QueryString["PressRelease_Request_ID"]);
            new ClientContractCityMapController().RequestStatusFlag_Check(id);
          }
          public string DecryptString(string encryptedPassword) {
            byte[] passByteData = Convert.FromBase64String(encryptedPassword);
            return System.Text.Encoding.Unicode.GetString(passByteData);
          }
          protected void btnSubmit_Click(object sender, EventArgs e) {
            fuApproval.SaveAs("x");
            new ClientContractCityMapController().Client_Approval_Update(obj);
          }
        }
        """
    )

    findings = source_audit.scan_source_tree(src)

    assert any(f.rule_id == "source.base64_link_authorization" and f.vtype == "auth_bypass" for f in findings)


def test_source_audit_flags_unauthenticated_query_report_download(tmp_path: Path):
    src = tmp_path / "app"
    src.mkdir()
    (src / "MailListDownload.aspx.cs").write_text(
        """
        public partial class MailListDownload : System.Web.UI.Page {
          protected void Page_Load(object sender, EventArgs e) {
            string cityId = Request.QueryString["CityID"];
            DataSet ds = new ClientContractCityMapController().GetMediaListList(Convert.ToInt32(cityId));
            GenerateMediaList(ds.Tables[0]);
          }
          private void GenerateMediaList(DataTable dt) {
            Byte[] bytes = viewer.LocalReport.Render("EXCEL");
            Response.BinaryWrite(bytes);
          }
        }
        """
    )

    findings = source_audit.scan_source_tree(src)

    assert any(f.rule_id == "source.unauthenticated_object_download" and f.vtype == "idor" for f in findings)


def test_source_audit_writes_report_folders(tmp_path: Path):
    src = tmp_path / "app"
    out = tmp_path / "findings"
    src.mkdir()
    (src / "Web.config").write_text(
        '<add key="Password" value="PLACEHOLDER_CONFIG_SECRET_VALUE" />'
    )

    findings = source_audit.scan_source_tree(src)
    counts = source_audit.write_findings(findings, out, src)

    assert counts["exposure"] == 1
    assert (out / "exposure" / "source_audit.txt").is_file()
    assert (out / "manual_review" / "source_audit.json").is_file()
