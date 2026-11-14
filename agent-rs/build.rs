//! Иконка exe — тот же пиксельный глаз, что в окне: рисует src/brand.rs (только стандартная библиотека).
//! Заодно кладёт иконку и картинку мастера в build\ репозитория — их берёт установщик (packaging/deepsec.iss).

#[path = "src/brand.rs"]
mod brand;

fn main() {
    println!("cargo:rerun-if-changed=src/brand.rs");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let ico = out.join("deepsec.ico");
    std::fs::write(&ico, brand::ico_bytes()).unwrap();
    let repo_build = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("build");
    let _ = std::fs::create_dir_all(&repo_build);
    std::fs::write(repo_build.join("deepsec.ico"), brand::ico_bytes()).unwrap();
    std::fs::write(repo_build.join("wizard-small.bmp"), brand::wizard_bmp(110)).unwrap();

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon(ico.to_str().unwrap())
            .set("ProductName", "DeepSec Agent")
            .set("FileDescription", "DeepSec — защита сессий Telegram Desktop")
            .set("CompanyName", "DeepSec");
        res.compile().expect("ресурсы exe (иконка) не собрались");
    }
}
