// Package mcp implements a minimal Model Context Protocol server: JSON-RPC 2.0
// framed as one message per line over stdio. It knows nothing about Cifra —
// callers register Tools whose handlers do the real work.
package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// protocolVersion is the MCP protocol revision this server speaks.
const protocolVersion = "2024-11-05"

// maxMessageBytes bounds a single JSON-RPC line (tool call results can carry
// command output, so allow more than bufio.Scanner's 64KiB default).
const maxMessageBytes = 10 << 20

// Tool is a single MCP tool: its JSON Schema contract and the function that
// executes it. Handler receives the raw "arguments" object from the tools/call
// request and returns a JSON-serializable result or an error.
type Tool struct {
	Name        string
	Description string
	InputSchema json.RawMessage
	Handler     func(arguments json.RawMessage) (interface{}, error)
}

// Server dispatches JSON-RPC requests read from stdio to registered Tools.
type Server struct {
	Name    string
	Version string
	Tools   []Tool
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads newline-delimited JSON-RPC requests from r and writes responses
// to w until r is exhausted or returns an error. Notifications (requests with
// no id) never produce a response, per JSON-RPC 2.0.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxMessageBytes)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		s.handle(line, w)
	}
	return scanner.Err()
}

func (s *Server) handle(line []byte, w io.Writer) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		s.writeResponse(w, nil, nil, &rpcError{Code: -32700, Message: "parse error"})
		return
	}

	result, rpcErr := s.dispatch(req.Method, req.Params)

	// A request with no id is a notification — JSON-RPC forbids a response.
	if len(req.ID) == 0 {
		return
	}
	s.writeResponse(w, req.ID, result, rpcErr)
}

func (s *Server) dispatch(method string, params json.RawMessage) (interface{}, *rpcError) {
	switch method {
	case "initialize":
		return map[string]interface{}{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo":      map[string]interface{}{"name": s.Name, "version": s.Version},
		}, nil
	case "notifications/initialized", "notifications/cancelled":
		return nil, nil
	case "tools/list":
		return map[string]interface{}{"tools": s.toolDescriptors()}, nil
	case "tools/call":
		return s.callTool(params)
	case "ping":
		return map[string]interface{}{}, nil
	default:
		return nil, &rpcError{Code: -32601, Message: "method not found: " + method}
	}
}

func (s *Server) toolDescriptors() []map[string]interface{} {
	out := make([]map[string]interface{}, len(s.Tools))
	for i, t := range s.Tools {
		out[i] = map[string]interface{}{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		}
	}
	return out
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// callTool executes a tools/call request. Tool execution errors are reported
// as a successful JSON-RPC response with isError:true (the MCP convention) so
// the model can see and react to them, rather than as protocol-level errors.
func (s *Server) callTool(params json.RawMessage) (interface{}, *rpcError) {
	var p toolCallParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid params"}
	}

	for _, t := range s.Tools {
		if t.Name != p.Name {
			continue
		}
		result, err := t.Handler(p.Arguments)
		if err != nil {
			return toolResult(err.Error(), true), nil
		}
		b, err := json.Marshal(result)
		if err != nil {
			return toolResult(err.Error(), true), nil
		}
		return toolResult(string(b), false), nil
	}
	return nil, &rpcError{Code: -32602, Message: "unknown tool: " + p.Name}
}

func toolResult(text string, isError bool) map[string]interface{} {
	return map[string]interface{}{
		"content": []map[string]interface{}{{"type": "text", "text": text}},
		"isError": isError,
	}
}

// PrintSchemas writes the JSON Schema of every registered tool to w, pretty
// printed as a single JSON array. Used by `cifra mcp serve --dry-run` for
// debugging and for generating the plugin manifest's tool documentation.
func (s *Server) PrintSchemas(w io.Writer) error {
	b, err := json.MarshalIndent(s.toolDescriptors(), "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

func (s *Server) writeResponse(w io.Writer, id json.RawMessage, result interface{}, rpcErr *rpcError) {
	resp := rpcResponse{JSONRPC: "2.0", ID: id, Result: result, Error: rpcErr}
	b, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintln(w, `{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error"}}`) //nolint:errcheck,gosec
		return
	}
	fmt.Fprintf(w, "%s\n", b) //nolint:errcheck,gosec
}
