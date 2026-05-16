from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db.models import Base, EmailAnalysis
import os

# Creamos la base de datos SQLite en la raíz del proyecto
DATABASE_URL = "sqlite:///phishing_detector.db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)


def init_db():
    """Crea las tablas si no existen."""
    Base.metadata.create_all(engine)


def save_analysis(analysis: dict) -> EmailAnalysis:
    """Guarda un análisis en la base de datos."""
    db = SessionLocal()
    try:
        record = EmailAnalysis(
            email_id             = analysis["email_id"],
            subject              = analysis["subject"],
            sender               = analysis["sender"],
            classification       = analysis["classification"],
            risk_score           = analysis["risk_score"],
            severity             = analysis["severity"],
            mitre_technique      = analysis["mitre_technique"],
            mitre_technique_name = analysis["mitre_technique_name"],
            attack_summary       = analysis["attack_summary"],
            recommended_action   = analysis["recommended_action"],
            reasons              = analysis["reasons"],
            iocs                 = analysis["iocs"],
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_analysis(email_id: str) -> EmailAnalysis:
    """Recupera un análisis por email_id."""
    db = SessionLocal()
    try:
        return db.query(EmailAnalysis).filter(
            EmailAnalysis.email_id == email_id
        ).first()
    finally:
        db.close()


def get_recent_analyses(limit: int = 10) -> list:
    """Recupera los últimos análisis realizados."""
    db = SessionLocal()
    try:
        return db.query(EmailAnalysis).order_by(
            EmailAnalysis.analyzed_at.desc()
        ).limit(limit).all()
    finally:
        db.close()


def already_analyzed(email_id: str) -> bool:
    """Comprueba si un email ya fue analizado anteriormente."""
    return get_analysis(email_id) is not None