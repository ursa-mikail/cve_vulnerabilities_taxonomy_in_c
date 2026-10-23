.PHONY: up down clean logs

up:
	docker compose up --build -d
	@echo ""
	@echo "Ready -> http://localhost:8080"
	@echo "(run 'make logs' to watch the containers, 'make down' to stop, 'make clean' to wipe everything)"

down:
	docker compose down

clean:
	docker compose down -v --rmi local --remove-orphans

logs:
	docker compose logs -f
