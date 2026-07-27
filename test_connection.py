# test_connection.py — corre esto antes de levantar la app
from dotenv import load_dotenv
load_dotenv()

from app.Core.db.cgc_db_loader import get_db_loader

loader = get_db_loader()
health = loader.health_check()
print("Health:", health)
# Esperado: {'status': 'OK', 'db': 'connected', 'ecm_rows': 6}

banking = loader.get_ecm("BANKING")
print("ECM Banking keys:", list(banking.keys()))
# Esperado: ['base_frameworks', 'sensitivity_modulation', ...]