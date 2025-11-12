package main
import (
	"io"
	"os"
)

func TrackedReadFile(name string) ([]byte, error) {
	data, err := os.ReadFile(name)
	if err == nil {
		TrackDiskRead(int64(len(data)))
	}
	return data, err
}

func TrackedWriteFile(name string, data []byte, perm os.FileMode) error {
	err := os.WriteFile(name, data, perm)
	if err == nil {
		TrackDiskWrite(int64(len(data)))
	}
	return err
}

func TrackedCopy(dst io.Writer, src io.Reader) (written int64, err error) {
	written, err = io.Copy(dst, src)
	if err == nil {
		
		TrackDiskWrite(written)
	}
	return written, err
}

func TrackedCreate(name string) (*TrackedFile, error) {
	file, err := os.Create(name)
	if err != nil {
		return nil, err
	}
	return &TrackedFile{File: file, isWrite: true}, nil
}

func TrackedOpen(name string) (*TrackedFile, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	return &TrackedFile{File: file, isWrite: false}, nil
}

type TrackedFile struct {
	*os.File
	isWrite bool
}
func (tf *TrackedFile) Read(b []byte) (n int, err error) {
	n, err = tf.File.Read(b)
	if n > 0 {
		TrackDiskRead(int64(n))
	}
	return n, err
}
func (tf *TrackedFile) Write(b []byte) (n int, err error) {
	n, err = tf.File.Write(b)
	if n > 0 {
		TrackDiskWrite(int64(n))
	}
	return n, err
}
