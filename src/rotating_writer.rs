use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

type FileInitializer = dyn Fn(&mut BufWriter<File>) -> io::Result<()>;

pub struct RotatingFileWriter {
    base_path: PathBuf,
    max_size: u64,
    current_file: Option<BufWriter<File>>,
    current_size: u64,
    file_count: u32,
    file_extension: String,
    init_new_file: Box<FileInitializer>,
}

impl RotatingFileWriter {
    pub fn new<F>(
        base_path: PathBuf,
        max_size: u64,
        file_extension: &str,
        init_new_file: F,
    ) -> io::Result<Self>
    where
        F: Fn(&mut BufWriter<File>) -> io::Result<()> + 'static,
    {
        if max_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "maximum file size must be greater than zero",
            ));
        }

        let mut writer = RotatingFileWriter {
            base_path,
            max_size,
            current_file: None,
            current_size: 0,
            file_count: 0,
            file_extension: file_extension.to_string(),
            init_new_file: Box::new(init_new_file),
        };
        writer.open_log_file()?;
        if writer.current_size >= writer.max_size {
            writer.rotate()?;
        }
        Ok(writer)
    }

    fn current_log_path(&self) -> PathBuf {
        self.base_path.with_extension("log")
    }

    fn rotation_target_path(&mut self) -> io::Result<PathBuf> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::Error::other("time went backwards"))?
            .as_micros();
        let base_name = self
            .base_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("muonfp");

        loop {
            let file_name = format!(
                "{}_{:016}_{:04}.{}",
                base_name, timestamp, self.file_count, self.file_extension
            );
            self.file_count = self.file_count.saturating_add(1);
            let candidate = self.current_log_path().with_file_name(file_name);
            if !candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    fn open_log_file(&mut self) -> io::Result<()> {
        let log_path = self.current_log_path();
        if let Some(parent) = log_path.parent() {
            create_dir_all(parent)?;
        }
        let existing_size = log_path
            .metadata()
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let mut buf_writer = BufWriter::new(file);
        if existing_size == 0 {
            (self.init_new_file)(&mut buf_writer)?;
        }
        buf_writer.flush()?;
        let current_size = buf_writer.get_ref().metadata()?.len();
        self.current_file = Some(buf_writer);
        self.current_size = current_size;
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.current_file.take() {
            file.flush()?;
        }
        let log_path = self.current_log_path();
        if log_path.exists() {
            let rotated_path = self.rotation_target_path()?;
            std::fs::rename(&log_path, rotated_path)?;
        }
        self.open_log_file()?;
        Ok(())
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let packet_size = packet.len() as u64;
        if self.current_size + packet_size > self.max_size {
            self.rotate()?;
        }
        if let Some(file) = self.current_file.as_mut() {
            file.write_all(packet)?;
            self.current_size += packet_size;
            Ok(())
        } else {
            Err(io::Error::other("no file currently open"))
        }
    }

    pub fn flush_and_close(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.current_file.take() {
            file.flush()?;
        }
        Ok(())
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_packet(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.current_file.as_mut() {
            file.flush()
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn rejects_zero_maximum_size() {
        let directory = tempdir().expect("temporary directory");
        let result = RotatingFileWriter::new(directory.path().join("muonfp"), 0, "out", |_| Ok(()));
        assert!(result.is_err());
    }

    #[test]
    fn preserves_active_log_across_restart() {
        let directory = tempdir().expect("temporary directory");
        let base_path = directory.path().join("muonfp");

        {
            let mut writer = RotatingFileWriter::new(base_path.clone(), 1024, "out", |_| Ok(()))
                .expect("first writer");
            writer.write_all(b"first\n").expect("first write");
            writer.flush().expect("first flush");
        }

        {
            let mut writer =
                RotatingFileWriter::new(base_path, 1024, "out", |_| Ok(())).expect("second writer");
            writer.write_all(b"second\n").expect("second write");
            writer.flush_and_close().expect("second close");
        }

        let contents =
            fs::read_to_string(directory.path().join("muonfp.log")).expect("read preserved log");
        assert_eq!(contents, "first\nsecond\n");
    }

    #[test]
    fn initializes_new_files_only_once() {
        let directory = tempdir().expect("temporary directory");
        let base_path = directory.path().join("packets");

        {
            let mut writer = RotatingFileWriter::new(base_path.clone(), 1024, "pcap", |file| {
                file.write_all(b"HEAD")
            })
            .expect("first writer");
            writer.write_all(b"one").expect("first write");
            writer.flush().expect("first flush");
        }

        {
            let mut writer =
                RotatingFileWriter::new(base_path, 1024, "pcap", |file| file.write_all(b"HEAD"))
                    .expect("second writer");
            writer.write_all(b"two").expect("second write");
            writer.flush_and_close().expect("second close");
        }

        let contents = fs::read(directory.path().join("packets.log")).expect("read packet log");
        assert_eq!(contents, b"HEADonetwo");
    }

    #[test]
    fn rotates_without_overwriting_existing_files() {
        let directory = tempdir().expect("temporary directory");
        let base_path = directory.path().join("muonfp");
        let mut writer =
            RotatingFileWriter::new(base_path, 5, "out", |_| Ok(())).expect("rotating writer");

        writer.write_all(b"first").expect("first write");
        writer.write_all(b"second").expect("rotating write");
        writer.flush().expect("flush current file");

        let mut rotated = fs::read_dir(directory.path())
            .expect("list output")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("out"))
            .collect::<Vec<_>>();
        rotated.sort();

        assert_eq!(rotated.len(), 1);
        assert_eq!(fs::read(&rotated[0]).expect("read rotated file"), b"first");
        assert_eq!(
            fs::read(directory.path().join("muonfp.log")).expect("read active file"),
            b"second"
        );
    }
}
