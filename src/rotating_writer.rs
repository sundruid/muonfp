use std::fs::{File, OpenOptions};
use std::io::{self, Write, BufWriter};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct RotatingFileWriter {
    base_path: PathBuf,
    max_size: u64,
    current_file: Option<BufWriter<File>>,
    current_size: u64,
    file_count: u32,
    current_path: Option<PathBuf>,
    file_extension: String,
}

impl RotatingFileWriter {
    pub fn new(base_path: PathBuf, max_size: u64, file_extension: &str) -> io::Result<Self> {
        let mut writer = RotatingFileWriter {
            base_path,
            max_size,
            current_file: None,
            current_size: 0,
            file_count: 0,
            current_path: None,
            file_extension: file_extension.to_string(),
        };
        writer.rotate()?;
        Ok(writer)
    }

    fn rotate(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.current_file.take() {
            file.flush()?;
        }
        if let Some(current_path) = self.current_path.take() {
            if current_path.exists() {
                let new_path = current_path.with_extension(&self.file_extension);
                std::fs::rename(current_path, new_path)?;
            }
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let file_name = format!(
            "{}_{:010}_{:04}.part",
            self.base_path.file_name().unwrap().to_str().unwrap(),
            timestamp,
            self.file_count
        );
        let new_path = self.base_path.with_file_name(&file_name);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&new_path)?;
        self.current_file = Some(BufWriter::new(file));
        self.current_path = Some(new_path);
        self.current_size = 0;
        self.file_count += 1;
        Ok(())
    }

    pub fn write_packet(&mut self, buf: &[u8]) -> io::Result<()> {
        if let Some(file) = self.current_file.as_mut() {
            file.write_all(buf)?;
            file.flush()?;
            self.current_size += buf.len() as u64;
            
            if self.current_size >= self.max_size {
                self.rotate()?;
            }
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "No file currently open"))
        }
    }

    pub fn flush_and_close(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.current_file.take() {
            file.flush()?;
        }
        if let Some(current_path) = self.current_path.take() {
            if current_path.exists() {
                let new_path = current_path.with_extension(&self.file_extension);
                std::fs::rename(current_path, new_path)?;
            }
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