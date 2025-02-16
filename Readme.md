Below is a minimal README with **installation** instructions, how to run from the **command line**, and how to debug using **VS Code**.

---

# GitHub Scanner (gRPC)

A Go application that scans a GitHub organization's repositories against Rego policies via gRPC.

## Installation

1. **Clone this repository** (or place the source in your desired project folder).
2. **Create** a `.env` file in `src/` with the following:
   ```
   GITHUB_TOKEN=<YOUR_TOKEN>
   ORG_NAME=<YOUR_ORG>
   ```
3. **Install dependencies** (from the project root):
   ```bash
   go mod tidy
   ```

## Running from Command Line

1. **Start the Server**  
   ```bash
   cd src
   go run .
   ```
   This launches the gRPC server on `localhost:50051`.

2. **Run the Client** (in a second terminal window):
   ```bash
   go run ./client/grpc_client.go
   ```
   The client connects to the server and tests multiple Rego policies.

## Debugging in VS Code

create `.vscode/launch.json` like this:

```jsonc
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug Server",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/src/.",
      "envFile": "${workspaceFolder}/src/.env",
      "console": "internalConsole"
    },
    {
      "name": "Debug Client",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/client/grpc_client.go",
      "console": "integratedTerminal"
    }
  ],
  "compounds": [
    {
      "name": "Debug Server & Client",
      "configurations": ["Debug Server", "Debug Client"]
    }
  ]
}
```