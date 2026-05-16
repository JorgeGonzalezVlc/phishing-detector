from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()


class EmailAnalysis(Base):
    """
    Tabla que almacena cada análisis realizado.
    Cada fila es un email analizado.
    """
    __tablename__ = "email_analysis"

    id                   = Column(Integer, primary_key=True, autoincrement=True)
    email_id             = Column(String, unique=True, index=True)
    subject              = Column(String)
    sender               = Column(String)
    date                 = Column(String)

    # Resultado del análisis
    classification       = Column(String)
    risk_score           = Column(Integer)
    severity             = Column(String)
    mitre_technique      = Column(String)
    mitre_technique_name = Column(String)
    attack_summary       = Column(Text)
    recommended_action   = Column(String)

    # IOCs y razones guardados como JSON
    reasons              = Column(JSON)
    iocs                 = Column(JSON)

    # Cuándo se analizó
    analyzed_at          = Column(DateTime, default=datetime.utcnow)


class Campaign(Base):
    """
    Tabla para agrupar emails relacionados en campañas de phishing.
    Para uso futuro con RAG y correlación.
    """
    __tablename__ = "campaigns"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    name        = Column(String)
    description = Column(Text)
    created_at  = Column(DateTime, default=datetime.utcnow)