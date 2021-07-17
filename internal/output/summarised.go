package output

type Command struct {
	Query        string
	ResultStatus string
	ResultsTable []Results
}

type Results struct {
	Columns []Value
}

type Value string
