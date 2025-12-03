# WordPress Test Instance

## Quick Start

```bash
docker-compose up -d --build
```

## Commands

| Action | Command |
|--------|---------|
| Start | `docker-compose up -d` |
| Start with rebuild | `docker-compose up -d --build` |
| Stop | `docker-compose down` |
| Stop and remove volumes | `docker-compose down -v` |
| View logs | `docker-compose logs -f` |
| View WordPress logs | `docker-compose logs -f wordpress` |

## Access

- **Site URL**: http://172.17.0.1:8000
- **REST API**: http://172.17.0.1:8000/wp-json/

## Credentials

| User | Password | Role |
|------|----------|------|
| admin | admin | Administrator |
| subscriber | subscriber | Subscriber |
| contributor | contributor | Contributor |
| author | author | Author |
| editor | editor | Editor |

## Notes

- Wait ~30 seconds after first start for WordPress setup to complete
- Check logs for `[WP-Setup] WordPress setup complete!` message
- Volumes persist data between restarts; use `down -v` for clean slate
