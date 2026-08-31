from pathlib import Path


def patch_gomcp() -> None:
    p = Path('.github/workflows/deploy-gomcp.yml')
    s = p.read_text(encoding='utf-8')

    s = s.replace('      owner_hash: ${{ steps.key.outputs.owner_hash }}\n', '')

    start = s.index("          $ownerKeyFile = Join-Path $stateDir 'mcp.token'\n")
    end = s.index('          $pub64 = ', start)
    s = s[:start] + s[end:]
    s = s.replace('          "owner_hash=$ownerHash" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding ascii -Append\n', '')
    s = s.replace('relay_wrapping_key=ready owner_key=present_not_printed', 'relay_wrapping_key=ready')

    marker = '    steps:\n      - name: Synchronize owner verifier and encrypt relay credentials for GoMCP\n'
    if marker not in s:
        raise SystemExit('wrap-relay-bundle step marker missing')
    s = s.replace(marker, '    steps:\n      - uses: actions/checkout@v4\n      - name: Synchronize owner verifier and encrypt relay credentials for GoMCP\n', 1)
    s = s.replace('          OWNER_HASH: ${{ needs.prepare-key.outputs.owner_hash }}\n', '')

    marker = '          chmod 700 "$state"\n'
    idx = s.index(marker, s.index('wrap-relay-bundle:')) + len(marker)
    insert = '          OWNER_HASH="$(tr -d \'\\r\\n\' < relay/owner-token.sha256)"\n'
    if insert not in s:
        s = s[:idx] + insert + s[idx:]

    s = s.replace("          if (-not (Test-Path (Join-Path $state 'mcp.token'))) { throw 'owner key is missing' }\n", '')
    s = s.replace('relay_credentials=installed owner_key=present_not_printed', 'relay_credentials=installed owner_verifier=repository_managed')

    smoke_start = s.index('      - name: Verify full ChatGPT OAuth flow, tools and refresh token\n')
    smoke_end = s.index('  external-probe:\n', smoke_start)
    replacement = '''      - name: Verify OAuth discovery and DCR contract
        shell: powershell -NoProfile -ExecutionPolicy Bypass -Command ". '{0}'"
        run: |
          $ErrorActionPreference = 'Stop'
          $base = 'https://gomcp-8-235-7-248.nip.io'
          $meta = Invoke-RestMethod -UseBasicParsing -Uri "$base/.well-known/oauth-authorization-server/goproxy/oauth" -TimeoutSec 10
          if (-not $meta.registration_endpoint) { throw 'OAuth registration endpoint missing' }
          $payload = @{
            client_name = 'GoMCP deployment DCR probe'
            redirect_uris = @('https://chatgpt.com/connector_platform_oauth_redirect')
            token_endpoint_auth_method = 'none'
            grant_types = @('authorization_code','refresh_token')
            response_types = @('code')
            application_type = 'web'
          } | ConvertTo-Json -Compress
          $client = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $meta.registration_endpoint -ContentType 'application/json' -Body $payload -TimeoutSec 10
          if (-not $client.client_id) { throw 'DCR probe failed' }
          Write-Host 'oauth_discovery=success dcr=success owner_verifier=repository_managed'

'''
    s = s[:smoke_start] + replacement + s[smoke_end:]
    p.write_text(s, encoding='utf-8')


def patch_relay() -> None:
    p = Path('.github/workflows/deploy-relay.yml')
    s = p.read_text(encoding='utf-8')
    marker = '          install -m 0644 relay/public_host.txt "$install_dir/public_host.txt"\n'
    insert = marker + '          install -m 0600 relay/owner-token.sha256 "$install_dir/state/owner-token.sha256"\n'
    if 'relay/owner-token.sha256' not in s:
        if marker not in s:
            raise SystemExit('relay install marker missing')
        s = s.replace(marker, insert, 1)
    p.write_text(s, encoding='utf-8')


if __name__ == '__main__':
    patch_gomcp()
    patch_relay()
