//! Слежение за программами удалённого доступа — через них чаще всего «подключаются» к ПК.

use std::collections::HashSet;

pub const REMOTE_TOOLS: &[(&str, &str)] = &[
    ("anydesk.exe", "AnyDesk"),
    ("teamviewer.exe", "TeamViewer"),
    ("teamviewer_service.exe", "TeamViewer"),
    ("rustdesk.exe", "RustDesk"),
    ("rutserv.exe", "Remote Utilities / RMS"),
    ("rfusclient.exe", "Remote Utilities / RMS"),
    ("romserver.exe", "LiteManager"),
    ("aa_v3.exe", "Ammyy Admin"),
    ("aeroadmin.exe", "AeroAdmin"),
    ("rudesktop.exe", "RuDesktop"),
    ("winvnc.exe", "UltraVNC"),
    ("tvnserver.exe", "TightVNC"),
    ("vncserver.exe", "RealVNC"),
    ("screenconnect.clientservice.exe", "ScreenConnect"),
    ("supremo.exe", "Supremo"),
    ("supremoservice.exe", "Supremo"),
    ("dwagent.exe", "DWService"),
    ("meshagent.exe", "MeshCentral"),
    ("remoting_host.exe", "Chrome Remote Desktop"),
    ("parsecd.exe", "Parsec"),
    ("quickassist.exe", "Быстрая помощь Windows"),
    ("ngrok.exe", "ngrok (туннель наружу)"),
];

#[derive(Clone, Debug, PartialEq)]
pub struct FoundProcess {
    pub pid: u32,
    pub name: String,
    pub exe: String,
    pub tool: &'static str,
}

/// (pid, имя, путь exe) запущенных процессов.
pub type ProcessList = Vec<(u32, String, String)>;

#[derive(Default)]
pub struct RemoteToolWatcher {
    seen: HashSet<u32>,
}

impl RemoteToolWatcher {
    /// Процессы удалённого доступа, появившиеся с прошлого опроса (на первом — все запущенные).
    pub fn poll(&mut self, processes: &ProcessList) -> Vec<FoundProcess> {
        let current: Vec<FoundProcess> = processes
            .iter()
            .filter_map(|(pid, name, exe)| {
                let lower = name.to_lowercase();
                REMOTE_TOOLS.iter().find(|(n, _)| *n == lower).map(|(_, tool)| FoundProcess {
                    pid: *pid,
                    name: name.clone(),
                    exe: exe.clone(),
                    tool,
                })
            })
            .collect();
        let new = current.iter().filter(|p| !self.seen.contains(&p.pid)).cloned().collect();
        self.seen = current.iter().map(|p| p.pid).collect();
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_only_new() {
        let mut procs: ProcessList = vec![(10, "AnyDesk.exe".into(), r"C:\a\AnyDesk.exe".into()), (11, "notepad.exe".into(), r"C:\n.exe".into())];
        let mut watcher = RemoteToolWatcher::default();
        let first = watcher.poll(&procs);
        assert_eq!(first.iter().map(|p| (p.pid, p.tool)).collect::<Vec<_>>(), vec![(10, "AnyDesk")]);
        assert!(watcher.poll(&procs).is_empty());
        procs.push((12, "rustdesk.exe".into(), String::new()));
        assert_eq!(watcher.poll(&procs).iter().map(|p| p.pid).collect::<Vec<_>>(), vec![12]);
    }
}
