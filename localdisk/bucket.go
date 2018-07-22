package localdisk

// localDiskBucket satisfies the filestor.Bucket interface
type localDiskBucket struct {
	dir string
}
