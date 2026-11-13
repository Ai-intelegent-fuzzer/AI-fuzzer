from app.authorization.models import (
    AuthorizationDecision,
    AuthorizationDecisionResult,
    AuthorizationCheckRequest,
    IdentityRole,
    Permission,
    ResourceClassification,
    ResourceOperation,
    SyntheticIdentity,
    SyntheticResource,
)


ROLE_PERMISSIONS: dict[IdentityRole, frozenset[Permission]] = {
    IdentityRole.ADMIN: frozenset(Permission),
    IdentityRole.MANAGER: frozenset({
        Permission.RESOURCE_READ,
        Permission.RESOURCE_WRITE,
        Permission.READ_OWNED,
        Permission.READ_TENANT,
        Permission.READ_MANAGER,
        Permission.WRITE_OWNED,
    }),
    IdentityRole.USER: frozenset({
        Permission.RESOURCE_READ,
        Permission.READ_OWNED,
        Permission.READ_TENANT,
        Permission.READ_PUBLIC,
    }),
    IdentityRole.GUEST: frozenset({
        Permission.RESOURCE_READ,
        Permission.READ_PUBLIC,
    }),
}


class AuthorizationPolicy:
    def __init__(self, store) -> None:
        self._store = store

    def decide(self, request: AuthorizationCheckRequest) -> AuthorizationDecisionResult:
        identity = self._store.get_identity(request.identity_id)
        if identity is None or identity.authentication_status.value != "authenticated":
            return self._result(
                request,
                AuthorizationDecision.INVALID_IDENTITY,
                "The synthetic identity does not exist or is not authenticated.",
            )
        if identity.session_id != request.session_id:
            return self._result(
                request,
                AuthorizationDecision.INVALID_SESSION,
                "The supplied synthetic session does not match the identity session.",
            )
        if request.context_identity_id is not None and request.context_identity_id != identity.identity_id:
            return self._result(
                request,
                AuthorizationDecision.INVALID_IDENTITY,
                "Application identity and request context identity do not match.",
            )

        resource = self._store.get_synthetic_resource(request.resource_id)
        if resource is None:
            return self._result(
                request,
                AuthorizationDecision.DENIED,
                "The requested resource is not in the controlled synthetic resource set.",
            )
        return self.decide_resource(request, resource)

    def decide_resource(
        self,
        request: AuthorizationCheckRequest,
        resource: SyntheticResource,
    ) -> AuthorizationDecisionResult:
        identity = self._store.get_identity(request.identity_id)
        if identity is None or identity.authentication_status.value != "authenticated":
            return self._result(
                request,
                AuthorizationDecision.INVALID_IDENTITY,
                "The synthetic identity does not exist or is not authenticated.",
            )
        if identity.session_id != request.session_id:
            return self._result(
                request,
                AuthorizationDecision.INVALID_SESSION,
                "The supplied synthetic session does not match the identity session.",
            )
        if request.context_identity_id is not None and request.context_identity_id != identity.identity_id:
            return self._result(
                request,
                AuthorizationDecision.INVALID_IDENTITY,
                "Application identity and request context identity do not match.",
            )
        permissions = self._permissions_for(identity)
        is_admin = IdentityRole.ADMIN in identity.roles
        if (
            resource.classification != ResourceClassification.PUBLIC
            and resource.tenant_id != identity.tenant_id
            and not is_admin
        ):
            return self._result(
                request,
                AuthorizationDecision.TENANT_MISMATCH,
                "The resource belongs to a different tenant.",
            )

        required_operation_permission = (
            Permission.RESOURCE_READ
            if request.operation == ResourceOperation.READ
            else Permission.RESOURCE_WRITE
        )
        if required_operation_permission not in permissions:
            return self._result(
                request,
                AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
                f"The identity lacks {required_operation_permission.value}.",
            )

        if not is_admin:
            if request.operation == ResourceOperation.WRITE:
                if (
                    resource.owner_identity_id != identity.identity_id
                    or Permission.WRITE_OWNED not in permissions
                ):
                    return self._result(
                        request,
                        AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
                        "Write access is limited to resources owned by the requesting identity.",
                    )
            elif not self._can_read_resource(identity, resource, permissions):
                return self._result(
                    request,
                    AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
                    "The identity lacks the resource-specific permission or ownership.",
                )

        missing_permissions = set(resource.required_permissions) - permissions
        if missing_permissions and not is_admin:
            missing = ", ".join(sorted(permission.value for permission in missing_permissions))
            return self._result(
                request,
                AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
                f"The resource requires permission(s): {missing}.",
            )

        return self._result(
            request,
            AuthorizationDecision.ALLOWED,
            "The synthetic identity is authorized by the application policy.",
        )

    @staticmethod
    def _permissions_for(identity: SyntheticIdentity) -> set[Permission]:
        permissions = set(identity.permissions)
        for role in identity.roles:
            permissions.update(ROLE_PERMISSIONS[role])
        return permissions

    @staticmethod
    def _can_read_resource(
        identity: SyntheticIdentity,
        resource: SyntheticResource,
        permissions: set[Permission],
    ) -> bool:
        if resource.classification == ResourceClassification.PUBLIC:
            return Permission.READ_PUBLIC in permissions
        if resource.classification == ResourceClassification.PRIVATE:
            return (
                resource.owner_identity_id == identity.identity_id
                and Permission.READ_OWNED in permissions
            )
        if resource.classification == ResourceClassification.MANAGER:
            return Permission.READ_MANAGER in permissions
        if resource.classification == ResourceClassification.ADMIN:
            return False
        return Permission.READ_TENANT in permissions

    @staticmethod
    def _result(
        request: AuthorizationCheckRequest,
        decision: AuthorizationDecision,
        reason: str,
    ) -> AuthorizationDecisionResult:
        return AuthorizationDecisionResult(
            decision=decision,
            allowed=decision == AuthorizationDecision.ALLOWED,
            reason=reason,
            requesting_identity_id=request.identity_id,
            resource_id=request.resource_id,
            operation=request.operation,
        )
