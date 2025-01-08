# pbsanitize

I needed a tool to safely sanitize secrets and sensitive data before copying to clipboard, so I made this. It automatically detects and redacts things like API keys, tokens, passwords, SSH keys, and other secrets.

## Install

### On macOS
```bash
git clone https://github.com/janpreet/pbsanitize
cd pbsanitize
make
sudo make install
```

### On Linux
First install xsel:
```bash
sudo apt install xsel  # Ubuntu/Debian
sudo dnf install xsel  # Fedora
```

Then build and install:
```bash
git clone https://github.com/janpreet/pbsanitize
cd pbsanitize
make
sudo make install
```

## Usage

Just pipe any text through it:
```bash
cat config.yml | pbsanitize
git config -l | pbsanitize
echo "my_api_key=secret123" | pbsanitize
```

The sanitized output is automatically copied to your clipboard.

## What it catches

- API keys & secrets
- AWS keys & cloud credentials
- JWT tokens
- GitHub tokens
- Private keys & certificates
- Connection strings
- Email addresses
- Credit card numbers
- Environment variables
- IPs (v4 & v6)
- SSH keys
- OAuth tokens
- Session IDs
- Etc.

## License

MIT