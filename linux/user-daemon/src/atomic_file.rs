use std::fs;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub(crate) fn overwrite<W>(path: &Path, writer_fn: W) -> io::Result<()>
where
    W: FnOnce(Box<&mut dyn Write>) -> io::Result<()>,
{
    let directory = path.parent().ok_or(io::Error::new(
        io::ErrorKind::InvalidInput,
        "Invalid file path, does not have a parent directory",
    ))?;
    let tmp_path = make_tmp_path(path)?;

    {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        writer_fn(Box::new(&mut tmp_file))?;
        tmp_file.flush()?;
        tmp_file.sync_all()?;
    }

    fs::rename(&tmp_path, path)?;
    fsync_dir(directory)?;
    Ok(())
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    let f = File::open(dir)?;
    f.sync_all()
}

fn make_tmp_path(path: &Path) -> io::Result<PathBuf> {
    let mut tmp_path = PathBuf::from(path);
    let mut file_name = tmp_path
        .file_name()
        .ok_or(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid file path, does not end in a file name",
        ))?
        .to_owned();
    file_name.push(".tmp");
    tmp_path.set_file_name(file_name);
    Ok(tmp_path)
}
