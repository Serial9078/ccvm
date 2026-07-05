from sqlalchemy.orm import Session
from app.models.customer import Customer


class CustomerRepository:
    def __init__(self, db: Session):
        self.db = db

    def list(self) -> list[Customer]:
        return self.db.query(Customer).order_by(Customer.id.desc()).all()

    def create(self, name: str, email: str | None) -> Customer:
        customer = Customer(name=name, email=email)
        self.db.add(customer)
        self.db.commit()
        self.db.refresh(customer)
        return customer
