from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    model = User

    list_display = (
        'email_address', 'username', 'account_type',
        'is_active', 'is_staff', 'created_at'
    )
    list_filter = ('account_type', 'is_active', 'is_staff', 'created_at')
    search_fields = ('email_address', 'username', 'phone_number')
    ordering = ("-created_at",)

    # auto-managed fields are read-only
    readonly_fields = ('created_at', 'updated_at')

    fieldsets = (
        (None, {"fields": ("email_address", "password")}),
        ("Personal info", {
            "fields": ("username", "phone_number", "country", "state", "address")
        }),
        ("Verification", {
            "fields": ("verified_at", "verification_code") 
        }),
        ("Password Reset", {
            "fields": ("password_reset_token", "password_reset_expires_at") 
        }),
        ("Permissions", {
            "fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")
        }),
        ("Important dates", {
            "fields": ("last_login",) 
        }),
    )

    add_fieldsets = (
        (None, {
            'classes': ("wide",),
            "fields": (
                "email_address", "username", "account_type",
                "password1", "password2", "is_active", "is_staff"
            ),
        }),
    )
