#!/usr/bin/env python3
"""
Security and cryptographic utilities for governance.
Provides encryption, authentication, and security validation.
"""

import os
import json
import hashlib
import hmac
import secrets
import logging
from typing import Dict, Any, Tuple, Optional
from datetime import datetime, timedelta
from functools import wraps
import base64

logger = logging.getLogger(__name__)


class SecurityKey:
    """Represents a cryptographic key with rotation tracking."""

    def __init__(self, key_type: str, key_value: str, rotation_period: int = 86400):
        self.key_type = key_type
        self.key_value = key_value
        self.created_at = datetime.utcnow()
        self.rotation_period = rotation_period
        self.rotations = []

    def needs_rotation(self) -> bool:
        """Check if key needs rotation."""
        age = (datetime.utcnow() - self.created_at).total_seconds()
        return age > self.rotation_period

    def rotate(self) -> str:
        """Rotate key and return new key."""
        self.rotations.append({
            "rotated_at": datetime.utcnow().isoformat(),
            "old_key_hash": hashlib.sha256(self.key_value.encode()).hexdigest()
        })
        self.key_value = secrets.token_urlsafe(32)
        self.created_at = datetime.utcnow()
        logger.info(f"Key {self.key_type} rotated")
        return self.key_value


class CryptographicUtils:
    """Cryptographic utilities for secure operations."""

    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash password with salt."""
        if salt is None:
            salt = secrets.token_hex(16)

        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt.encode(),
            100000
        )
        return salt + ':' + base64.b64encode(password_hash).decode(), salt

    @staticmethod
    def verify_password(stored_hash: str, provided_password: str) -> bool:
        """Verify password against stored hash."""
        try:
            salt, hash_value = stored_hash.split(':')
            provided_salt = salt
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                provided_password.encode(),
                provided_salt.encode(),
                100000
            )
            return hmac.compare_digest(
                base64.b64encode(password_hash).decode(),
                hash_value
            )
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False

    @staticmethod
    def generate_signature(data: Dict[str, Any], secret_key: str) -> str:
        """Generate HMAC signature for data."""
        json_data = json.dumps(data, sort_keys=True)
        signature = hmac.new(
            secret_key.encode(),
            json_data.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature

    @staticmethod
    def verify_signature(data: Dict[str, Any], signature: str, secret_key: str) -> bool:
        """Verify HMAC signature."""
        expected_signature = CryptographicUtils.generate_signature(data, secret_key)
        return hmac.compare_digest(signature, expected_signature)

    @staticmethod
    def encrypt_data(data: str, key: str) -> str:
        """Simple XOR-based encryption (for MVP - use proper encryption in production)."""
        key_hash = hashlib.sha256(key.encode()).digest()
        encrypted = bytearray()
        for i, char in enumerate(data.encode()):
            encrypted.append(char ^ key_hash[i % len(key_hash)])
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def decrypt_data(encrypted_data: str, key: str) -> str:
        """Simple XOR-based decryption (for MVP - use proper encryption in production)."""
        try:
            key_hash = hashlib.sha256(key.encode()).digest()
            encrypted = base64.b64decode(encrypted_data)
            decrypted = bytearray()
            for i, byte in enumerate(encrypted):
                decrypted.append(byte ^ key_hash[i % len(key_hash)])
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return ""

    @staticmethod
    def generate_token(user_id: str, secret_key: str, expiry_hours: int = 24) -> Tuple[str, str]:
        """Generate secure token with expiry."""
        expiry = (datetime.utcnow() + timedelta(hours=expiry_hours)).isoformat()
        payload = {
            "user_id": user_id,
            "issued_at": datetime.utcnow().isoformat(),
            "expires_at": expiry
        }
        signature = CryptographicUtils.generate_signature(payload, secret_key)
        token = base64.b64encode(
            json.dumps({**payload, "signature": signature}).encode()
        ).decode()
        return token, expiry

    @staticmethod
    def verify_token(token: str, secret_key: str) -> Tuple[bool, Dict[str, Any]]:
        """Verify secure token."""
        try:
            decoded = json.loads(base64.b64decode(token))
            signature = decoded.pop("signature")
            expires_at = datetime.fromisoformat(decoded["expires_at"])

            if datetime.utcnow() > expires_at:
                logger.warning("Token expired")
                return False, {}

            if not CryptographicUtils.verify_signature(decoded, signature, secret_key):
                logger.warning("Invalid token signature")
                return False, {}

            return True, decoded
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return False, {}


class AuditTrail:
    """Immutable audit trail for security events."""

    def __init__(self, master_key: str):
        self.master_key = master_key
        self.events = []

    def log_event(self, event_type: str, actor: str, resource: str,
                  action: str, details: Dict[str, Any] = None) -> str:
        """Log a security event."""
        event = {
            "id": secrets.token_hex(16),
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "actor": actor,
            "resource": resource,
            "action": action,
            "details": details or {}
        }

        # Sign event
        event_signature = CryptographicUtils.generate_signature(
            {k: v for k, v in event.items() if k != "signature"},
            self.master_key
        )
        event["signature"] = event_signature

        self.events.append(event)
        logger.info(f"Security event logged: {event_type} by {actor}")
        return event["id"]

    def verify_event(self, event_id: str) -> bool:
        """Verify integrity of an event."""
        for event in self.events:
            if event["id"] == event_id:
                signature = event.pop("signature")
                is_valid = CryptographicUtils.verify_signature(
                    event,
                    signature,
                    self.master_key
                )
                event["signature"] = signature
                return is_valid
        return False

    def get_events_for_actor(self, actor: str) -> list:
        """Retrieve all events for an actor."""
        return [e for e in self.events if e["actor"] == actor]

    def get_events_for_resource(self, resource: str) -> list:
        """Retrieve all events for a resource."""
        return [e for e in self.events if e["resource"] == resource]

    def export_audit_trail(self, filepath: str) -> None:
        """Export audit trail to file."""
        with open(filepath, 'w') as f:
            json.dump({
                "exported_at": datetime.utcnow().isoformat(),
                "total_events": len(self.events),
                "events": self.events
            }, f, indent=2)
        logger.info(f"Audit trail exported to {filepath}")


class SecurityPolicy:
    """Security policy enforcement."""

    def __init__(self):
        self.policies = {}
        self.violations = []

    def add_policy(self, policy_name: str, conditions: Dict[str, Any],
                   enforcement: str = "block") -> None:
        """Add a security policy."""
        self.policies[policy_name] = {
            "conditions": conditions,
            "enforcement": enforcement,
            "created_at": datetime.utcnow().isoformat()
        }
        logger.info(f"Security policy added: {policy_name}")

    def check_policy(self, policy_name: str, context: Dict[str, Any]) -> Tuple[bool, str]:
        """Check if context violates a policy."""
        if policy_name not in self.policies:
            return True, "Policy not found"

        policy = self.policies[policy_name]
        conditions = policy["conditions"]

        # Check all conditions
        for condition_key, condition_value in conditions.items():
            if condition_key not in context:
                continue

            context_value = context[condition_key]

            if isinstance(condition_value, dict) and "min" in condition_value:
                if context_value < condition_value["min"]:
                    violation = {
                        "policy": policy_name,
                        "timestamp": datetime.utcnow().isoformat(),
                        "context": context,
                        "reason": f"Value {context_value} below minimum {condition_value['min']}"
                    }
                    self.violations.append(violation)
                    return False, violation["reason"]

            elif isinstance(condition_value, list):
                if context_value not in condition_value:
                    violation = {
                        "policy": policy_name,
                        "timestamp": datetime.utcnow().isoformat(),
                        "context": context,
                        "reason": f"Value {context_value} not in allowed values {condition_value}"
                    }
                    self.violations.append(violation)
                    return False, violation["reason"]

        return True, "Policy compliant"

    def get_violations(self) -> list:
        """Get all policy violations."""
        return self.violations


def require_authentication(func):
    """Decorator for authentication requirement."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        user_token = kwargs.get('token') or (args[0] if args else None)
        if not user_token:
            raise PermissionError("Authentication required")
        return func(*args, **kwargs)
    return wrapper


def audit_action(action_name: str):
    """Decorator for auditing actions."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger.info(f"Action {action_name} initiated")
            try:
                result = func(*args, **kwargs)
                logger.info(f"Action {action_name} completed successfully")
                return result
            except Exception as e:
                logger.error(f"Action {action_name} failed: {e}")
                raise
        return wrapper
    return decorator


# Example usage
if __name__ == "__main__":
    # Test cryptographic utilities
    print("=== Cryptographic Utilities Test ===")

    # Test password hashing
    password = "secure_password_123"
    hashed, salt = CryptographicUtils.hash_password(password)
    print(f"Password hashed: {hashed[:50]}...")
    print(f"Password verification: {CryptographicUtils.verify_password(hashed, password)}")

    # Test token generation
    token, expiry = CryptographicUtils.generate_token("user_123", "secret_key")
    print(f"\nToken generated, expires at: {expiry}")
    is_valid, payload = CryptographicUtils.verify_token(token, "secret_key")
    print(f"Token verification: {is_valid}")

    # Test data encryption
    data = "Sensitive data"
    encrypted = CryptographicUtils.encrypt_data(data, "encryption_key")
    decrypted = CryptographicUtils.decrypt_data(encrypted, "encryption_key")
    print(f"\nEncryption test: {decrypted == data}")

    # Test audit trail
    print("\n=== Audit Trail Test ===")
    audit_trail = AuditTrail("master_key")
    event_id = audit_trail.log_event(
        event_type="security_event",
        actor="admin",
        resource="sensitive_data",
        action="access",
        details={"ip": "192.168.1.1"}
    )
    print(f"Event logged with ID: {event_id}")
    print(f"Event verification: {audit_trail.verify_event(event_id)}")

    # Test security policy
    print("\n=== Security Policy Test ===")
    policy = SecurityPolicy()
    policy.add_policy(
        "rate_limit",
        {"requests_per_minute": {"min": 0}, "max": 100}
    )
    context = {"requests_per_minute": 50}
    compliant, reason = policy.check_policy("rate_limit", context)
    print(f"Policy compliance: {compliant} - {reason}")
