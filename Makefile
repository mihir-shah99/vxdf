# Makefile for VXDF Validate

.PHONY: dev check backend frontend

backend:
	cd api && python3 -m api.server --port 5001

frontend:
	cd frontend && npm run dev

dev:
	@echo "Starting backend and frontend..."
	@echo "Backend: http://localhost:5001"
	@echo "Frontend: http://localhost:3000"
	@echo "(Use two terminals: 'make backend' and 'make frontend')"

check:
	@echo "Checking backend API endpoints..."
	@curl -sf http://localhost:5001/api/stats && echo "[OK] /api/stats" || (echo "[FAIL] /api/stats" && exit 1)
	@curl -sf http://localhost:5001/api/vulnerabilities && echo "[OK] /api/vulnerabilities" || (echo "[FAIL] /api/vulnerabilities" && exit 1)
	@echo "All health checks passed." 