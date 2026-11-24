fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/setup.ico");
        res.set_manifest_file("app.manifest");
        res.set("FileDescription", "Просто Подпись — установка");
        res.set("ProductName", "Просто Подпись");
        res.set("CompanyName", "Просто Подпись");
        res.set("LegalCopyright", "Просто Подпись");
        let _ = res.compile();
    }
}
