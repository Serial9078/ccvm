from sqlalchemy.orm import Session

from app.repositories.customer_repository import CustomerRepository
from app.schemas.customer import CustomerCreate


class CustomerService:
    def __init__(self, db: Session):
        self.repo = CustomerRepository(db)

    def list_customers(self):
        return self.repo.list()

    def create_customer(self, payload: CustomerCreate):
        return self.repo.create(payload.name, payload.email)
