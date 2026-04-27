#!/bin/bash
set -e
cd /home/krishna/threatvision

echo "  Starting ThreatVision..."
echo ""

# Use docker compose v2 (docker-compose v1 has a ContainerConfig bug with newer images)
DC="docker compose"

# Start infrastructure
echo " Starting Docker services..."
$DC up -d postgres redis chromadb
echo ""

# Wait for Postgres with TCP check
echo " Waiting for Postgres on port 5432..."
for i in $(seq 1 30); do
    if python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1',5432)); s.close()" 2>/dev/null; then
        echo " Postgres is ready"
        break
    fi
    echo "   attempt $i/30..."
    sleep 2
done

# Wait for Redis with TCP check
echo " Waiting for Redis on port 6379..."
for i in $(seq 1 15); do
    if python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1',6379)); s.close()" 2>/dev/null; then
        echo " Redis is ready"
        break
    fi
    sleep 2
done

echo ""

# Check / bootstrap real datasets (one-time, ~200 MB)
echo " Checking real datasets..."
cd /home/krishna/threatvision/backend
MISSING=$(python3 -c "
from app.datasets.registry import is_cached, DATASETS
missing = [d for d in DATASETS if not is_cached(d)]
print(' '.join(missing))
" 2>/dev/null)
if [ -n "$MISSING" ]; then
    echo " Downloading real datasets (one-time, ~200 MB): $MISSING"
    python3 -m app.datasets download
    echo " Pre-training models on real data (runs in background)..."
    python3 -m app.datasets benchmark > /tmp/benchmark_results.txt 2>&1 &
    echo " Datasets downloaded — benchmark running in background"
else
    echo " Real datasets already cached"
fi
echo ""

# Seed database
echo " Seeding demo data..."
cd /home/krishna/threatvision/backend
python3 -m app.data.seed_db
echo " Demo data seeded"
echo " Seeding analysts and demo tickets..."
python3 -m app.data.seed_analysts
echo " Analysts seeded"
echo ""

# Start backend
echo " Starting backend API..."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --log-level warning &
BACKEND_PID=$!
sleep 8

# Verify backend started
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo " Backend running at http://localhost:8000"
else
    echo " Backend failed to start - check logs"
    exit 1
fi
echo ""

# Start frontend
echo " Starting frontend..."
cd /home/krishna/threatvision/frontend
npm run dev > /tmp/frontend.log 2>&1 &
FRONTEND_PID=$!
sleep 6

# Verify frontend started
if curl -s http://localhost:3000 > /dev/null 2>&1; then
    echo " Frontend running at http://localhost:3000"
else
    echo "  Frontend still starting (check /tmp/frontend.log)"
fi

echo ""
echo "════════════════════════════════════════"
echo " ThreatVision is LIVE!"
echo "   Dashboard:  http://localhost:3000/dashboard"
echo "   API:        http://localhost:8000"
echo "   API Docs:   http://localhost:8000/docs"
echo "════════════════════════════════════════"
echo ""
echo "Press Ctrl+C to stop all services"

trap "echo ''; echo 'Stopping...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; $DC stop; echo 'Done.'" EXIT
wait
