package utils

// Min and Max are kept as generic helpers for the ported BBR implementation.
type bbrOrdered interface {
	~int | ~int64 | ~uint | ~uint64 | ~float32 | ~float64
}

func Min[T bbrOrdered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func Max[T bbrOrdered](a, b T) T {
	if a > b {
		return a
	}
	return b
}
