fn main() {
    println!("cargo:rerun-if-changed=assets/app_icon.ico");
    #[cfg(windows)]
    {
        let mut resource = winres::WindowsResource::new();
        resource.set_icon("assets/app_icon.ico");
        resource.set("FileDescription", "Просто подпись");
        resource.set("ProductName", "Просто подпись");
        resource.set("CompanyName", "Просто подпись");
        if let Err(error) = resource.compile() {
            println!("cargo:warning=не удалось встроить иконку в exe: {error}");
        }
    }
}
