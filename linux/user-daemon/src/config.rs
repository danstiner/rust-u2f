use std::fs::File;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use directories::ProjectDirs;
use directories::UserDirs;
use serde::{Deserialize, Serialize};

use crate::atomic_file;
use crate::secret_store::SecretStoreType;

pub struct Config {
    data: ConfigFileData,
    dirs: AppDirs,
}

impl Config {
    pub fn load() -> io::Result<Config> {
        let dirs = AppDirs::new()?;
        Config::load_from_dirs(dirs)
    }

    fn load_from_dirs(dirs: AppDirs) -> io::Result<Config> {
        let file = ConfigFile::load_or_create(&dirs)?;
        Ok(Config {
            data: file.data,
            dirs,
        })
    }

    pub fn secret_store_type(&self) -> SecretStoreType {
        self.data.secret_store_type
    }

    pub fn data_local_dir(&self) -> &Path {
        &self.dirs.data_local_dir
    }

    pub fn home_dir(&self) -> &Path {
        &self.dirs.home_dir
    }
}

struct AppDirs {
    home_dir: PathBuf,
    config_dir: PathBuf,
    data_local_dir: PathBuf,
}

impl AppDirs {
    fn new() -> io::Result<Self> {
        let user_dirs = UserDirs::new().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Home directory path could not be determined",
            )
        })?;
        let project_dirs =
            ProjectDirs::from("com.github", "danstiner", "Rust U2F").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "Home directory path could not be determined",
                )
            })?;

        return Ok(AppDirs {
            home_dir: user_dirs.home_dir().to_owned(),
            config_dir: project_dirs.config_dir().to_owned(),
            data_local_dir: project_dirs.data_local_dir().to_owned(),
        });
    }
}

#[derive(Default, Serialize, Deserialize)]
struct ConfigFileData {
    secret_store_type: SecretStoreType,
}

struct ConfigFile {
    data: ConfigFileData,
    path: PathBuf,
}

impl ConfigFile {
    fn load_or_create(dirs: &AppDirs) -> io::Result<ConfigFile> {
        let path = ConfigFile::path(dirs);

        if let Some(file) = ConfigFile::read(&path)? {
            return Ok(file);
        }

        ConfigFile::create(&path)
    }

    fn path(dirs: &AppDirs) -> PathBuf {
        dirs.config_dir.join("config.json")
    }

    fn create(path: &Path) -> io::Result<ConfigFile> {
        let config_file = ConfigFile {
            data: Default::default(),
            path: path.to_owned(),
        };
        config_file.save()?;
        Ok(config_file)
    }

    fn read(path: &Path) -> io::Result<Option<ConfigFile>> {
        match File::open(path) {
            Ok(file) => serde_json::from_reader(file)
                .map_err(|e| e.into())
                .map(|data| {
                    Some(ConfigFile {
                        data,
                        path: path.to_owned(),
                    })
                }),
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn save(&self) -> io::Result<()> {
        atomic_file::overwrite(&self.path, move |writer| {
            serde_json::to_writer_pretty(writer, &self.data).map_err(|e| e.into())
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate tempdir;

    use super::*;

    use self::tempdir::TempDir;

    #[test]
    fn load_with_not_existing_file_returns_none() {
        let temp_dir = TempDir::new("config_tests").unwrap();
        let dirs = AppDirs {
            config_dir: temp_dir.path().to_owned(),
            data_local_dir: PathBuf::new(),
            home_dir: PathBuf::new(),
        };
        let file_path = ConfigFile::path(&dirs);

        assert!(ConfigFile::read(&file_path).unwrap().is_none());
    }
}
