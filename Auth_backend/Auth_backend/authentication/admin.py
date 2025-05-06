from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, VerificationToken

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_verified', 'date_joined', 'last_login')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    list_filter = ('is_active', 'is_verified', 'is_staff', 'date_joined')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('OAuth Info', {'fields': ('google_id', 'github_id')}),
        ('Permissions', {'fields': ('is_active', 'is_verified', 'is_staff', 'is_superuser')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'is_staff', 'is_active', 'is_verified'),
        }),
    )

@admin.register(VerificationToken)
class VerificationTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token_type', 'created_at', 'expires_at', 'is_used')
    search_fields = ('user__email', 'token')
    list_filter = ('token_type', 'is_used', 'created_at')
    readonly_fields = ('token',)
