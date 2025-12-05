use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct RotatingFileWriter {
    base_path: PathBuf,
    max_size: u64,
    current_file: Option<BufWriter<File>>,
    current_size: u64,
    file_count: u32,
    file_extension: String,
    init_new_file: Box<dyn Fn(&mut BufWriter<File>) -> io::Result<()>>,
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
        Ok(writer)
    }

    fn current_log_path(&self) -> PathBuf {
        self.base_path.with_extension("log")
    }

    fn rotation_target_path(&self) -> io::Result<PathBuf> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Time went backwards"))?
            .as_secs();
        let base_name = self
            .base_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("muonfp");
        let file_name = format!(
            "{}_{:010}_{:04}.{}",
            base_name, timestamp, self.file_count, self.file_extension
        );
        Ok(self.current_log_path().with_file_name(file_name))
    }

    fn open_log_file(&mut self) -> io::Result<()> {
        let log_path = self.current_log_path();
        if let Some(parent) = log_path.parent() {
            create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&log_path)?;
        let mut buf_writer = BufWriter::new(file);
        (self.init_new_file)(&mut buf_writer)?;
        buf_writer.flush()?;
        self.current_file = Some(buf_writer);
        self.current_size = 0;
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
            self.file_count = self.file_count.saturating_add(1);
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
            Err(io::Error::new(
                io::ErrorKind::Other,
                "No file currently open",
            ))
        }
    }

    pub fn flush_and_close(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.current_file.take() {
            file.flush()?;
        }
        let log_path = self.current_log_path();
        if log_path.exists() {
            let rotated_path = self.rotation_target_path()?;
            std::fs::rename(&log_path, rotated_path)?;
            self.file_count = self.file_count.saturating_add(1);
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
