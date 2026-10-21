package query

// Page limits shared by REST, MCP and the query CLI. They are deliberately
// small: an agent should refine a query instead of pulling an unbounded result.
const (
	AgentMaxPageSize     = 200
	AgentDefaultMaxItems = 1000

	ChangeDefaultLimit = 100
	ChangeMaxLimit     = 1000

	AssetDefaultLimit = 20
	AssetMaxLimit     = 100
)
