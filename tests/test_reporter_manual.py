import reporter


def test_manual_report_workflow_is_available(tmp_path, monkeypatch):
    monkeypatch.setattr(reporter, "REPORTS_DIR", str(tmp_path / "reports"))

    report_dir, md_path, html_path = reporter.create_manual_report(
        "xss",
        "https://acme.example/search?q=test",
        param="q",
        evidence="Confirmed reflected payload",
    )

    assert tmp_path.joinpath("reports").exists()
    assert reporter.os.path.isdir(report_dir)
    assert reporter.os.path.isfile(md_path)
    assert reporter.os.path.isfile(html_path)

    with open(md_path, encoding="utf-8") as fh:
        md = fh.read()
    assert "Confirmed reflected payload" in md


def test_attach_poc_images_appends_markdown(tmp_path):
    report_file = tmp_path / "vapt_report.md"
    report_file.write_text("# Report\n", encoding="utf-8")
    image = tmp_path / "poc.png"
    image.write_bytes(b"fake-png")

    reporter.attach_poc_images(str(report_file), [str(image)])

    content = report_file.read_text(encoding="utf-8")
    assert "PoC Screenshots" in content
    assert "poc_screenshots/poc.png" in content
