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
}

impl RotatingFileWriter {
    pub fn new(base_path: PathBuf, max_size: u64) -> io::Result<Self> {
        let mut writer = RotatingFileWriter {
            base_path,
            max_size,
            current_file: None,
            current_size: 0,
            file_count: 0,
        };
        writer.rotate()?;
        Ok(writer)
    }

    fn rotate(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.current_file.take() {
            file.flush()?;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let file_name = format!("{}_{:010}_{:04}.out", 
            self.base_path.file_name().unwrap().to_str().unwrap(),
            timestamp,
            self.file_count
        );
        let new_path = self.base_path.with_file_name(file_name);

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(new_path)?;

        self.current_file = Some(BufWriter::new(file));
        self.current_size = 0;
        self.file_count += 1;

        Ok(())
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.current_size + buf.len() as u64 > self.max_size {
            self.rotate()?;
        }

        if let Some(file) = self.current_file.as_mut() {
            let bytes_written = file.write(buf)?;
            self.current_size += bytes_written as u64;
            Ok(bytes_written)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "No file currently open"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.current_file.as_mut() {
            file.flush()
        } else {
            Ok(())
        }
    }
}