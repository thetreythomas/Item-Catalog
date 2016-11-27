import sys

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250))


class Catalog(Base):
    __tablename__ = 'catalog'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)

    @property
    def serialize(self):
        "Return object data in easily serializable format"
        return {
            'name': self.name,
            'catalog id': self.id,
        }



class CatalogItem(Base):
    __tablename__ = 'catalog_item'

    id = Column(Integer, primary_key=True)
    item_name = Column(String(250), nullable=False)
    description = Column(String(250))
    catalog_id = Column(Integer, ForeignKey('catalog.id'))
    catalog = relationship(Catalog)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)


    @property
    def serialize(self):
        "Return object data in easily serializable format"
        return {
            'item_name': self.item_name,
            'description': self.description,
            'item id': self.id,
            'linked catalog id': self.catalog_id,
            'linked catalog name': self.catalog.name,
        }



engine = create_engine('sqlite:///itemcatalog.db')

Base.metadata.create_all(engine)