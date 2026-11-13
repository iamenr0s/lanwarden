from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import ItemId, get_db, require_user
from app.models.system import NotificationRule
from app.notifications.base import Message
from app.schemas.notifications import DeliveryOut, RuleIn, RuleOut, SendResult
from app.services import notification_rules as rules

router = APIRouter(prefix="/api/notifications", tags=["notifications"], dependencies=[Depends(require_user)])


def _provider(request: Request, name: str):
    return request.app.state.notifier.providers[name]


def _rule_or_404(db: Session, rule_id: ItemId) -> NotificationRule:
    rule = db.get(NotificationRule, rule_id)
    if rule is None:
        raise HTTPException(404, "Rule not found")
    return rule


@router.get("/rules", response_model=list[RuleOut])
def list_rules(request: Request, db: Session = Depends(get_db)):
    providers = request.app.state.notifier.providers
    return [rules.to_public(r, providers.get(r.provider)) for r in db.scalars(select(NotificationRule).order_by(NotificationRule.id))]


@router.post("/rules", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(body: RuleIn, request: Request, db: Session = Depends(get_db)):
    provider = _provider(request, body.provider)
    if missing := rules.missing_required(provider, body.config, None):
        raise HTTPException(422, f"Required: {', '.join(missing)}")
    return rules.to_public(rules.create(db, request.app.state.box, provider, body), provider)


@router.put("/rules/{rule_id}", response_model=RuleOut)
def update_rule(rule_id: ItemId, body: RuleIn, request: Request, db: Session = Depends(get_db)):
    rule = _rule_or_404(db, rule_id)
    if body.provider != rule.provider:
        raise HTTPException(422, "The provider of an existing rule cannot be changed; create a new rule")
    provider = _provider(request, rule.provider)
    if missing := rules.missing_required(provider, body.config, rule.config):
        raise HTTPException(422, f"Required: {', '.join(missing)}")
    return rules.to_public(rules.update(db, request.app.state.box, provider, rule, body), provider)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(rule_id: ItemId, db: Session = Depends(get_db)):
    db.delete(_rule_or_404(db, rule_id))
    db.commit()


@router.post("/rules/{rule_id}/test", response_model=SendResult)
def test_rule(rule_id: ItemId, request: Request, db: Session = Depends(get_db)):
    """Sends a test message through the saved rule. Always 200; failure is reported in the body."""
    rule = _rule_or_404(db, rule_id)
    message = Message(title="LanWarden test notification",
                      body="If you can read this, notifications from LanWarden are working.")
    error = request.app.state.notifier.deliver(rule, message, 0)
    return SendResult(ok=error is None, error=error)


@router.get("/deliveries", response_model=list[DeliveryOut])
def deliveries(request: Request):
    """The most recent deliveries (in memory, newest first)."""
    return list(request.app.state.notifier.deliveries)
