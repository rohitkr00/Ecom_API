from collections import defaultdict
import json
from celery import Celery
from django.utils import timezone
import io
import logging
import csv
import requests

from common.pagination import CustomPagination
from common.views import BaseViewSet, BaseAPIView, PublicAPIView
from rest_framework import status

from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.exceptions import APIException, PermissionDenied
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.exceptions import MethodNotAllowed
from common.permissions import (
    IsActiveUser,
    IsSuperAdmin,
    IsAdminOrSuperAdminOrEditor,
    IsAdminOrSuperAdmin,
)

from django.views.decorators.csrf import csrf_exempt

import users

from .serializers import (
    ActionImpactResultOptionsHistorySerializer,
    GroupCreateSerializer,
    GroupUpdateSerializer,
    InviteGroupAdminSerializer,
    OrganizationSerializer,
    DepartmentSerializer,
    MemberSerializer,
    QuickPreferenceSerializer,
    RecallMessageDetailSerializerAdmin,
    RecallMessageSerializer,
    RecallMessageDetailSerializer,
    MemberImportSerializer,
    GroupSerializer,
    HotButtonSerializer,
    RecallResponseCreateSerializer,
    SendHotButtonMessageSerializer,
    BrandSerializer,
    SalesforceTicketSerializer,
    SendDepartmentMessageSerializer,
    SendOrganizationMessageSerializer,
    DialpadWebhookSerializer,
    SalesforceLeadSerializer,
    RecallMessageUpdateSerializer,
    VerbSerializer,
    WeatherAlertsSerializer,
    ChecklistSerializer,
    RecallMessageCreateSerializer,
    RecallMessageCreatePollTemplateSerializer,
    MemberUserSignupSerializer,
    MemberUserAcceptInviteSerializer,
    RecallMessageWithPollCreateSerializer,
    RecallMessageWithAlertCreateSerializer,
    HotButtonUpdateSerializer,
    PollChoiceResponseSerializer,
    MemberVerifyCodeSerializer,
    MemberInviteSendOTPSerializer
    )

from .models import (
    ActionImpactResultOptions,
    ActionImpactResultOptionsHistory,
    Organization,
    Department,
    Member,
    QuickPreference,
    RecallMessage,
    RecallResponse,
    Group,
    HotButton,
    Brand,
    SalesforceTickets,
    Verb,
    WeatherAlerts,
    Checklist,
    RecallMessagePollChoice,
    TicketFile
)

from .functions import (
    dialpad_send_message,
    send_activation_code_for_accept_invite_admin,
    send_hot_button_message,
    send_code,
    waitlist_confirmation_email,
    send_activation_code_for_signup,
    send_activation_code_for_accept_invite,
    send_email_phone_otp,
)

from .salesforce import (
    get_salesforce_token,
    create_salesforce_ticket,
    create_salesforce_lead,
)

from common.permissions import IsSuperAdmin, IsActiveUser, IsAdminOrSuperAdmin
from common.functions import serailizer_errors

from users.models import EPBOPB, GenericPreference, GenericUserPreferences, User, Notification, UserPreference
from users.serializers import ChangePreferenceSerializer, EPBOPBSerializer, GenericPreferenceSerializer, GenericUserPreferencesSerializer, UserPreferencesSerializer, UserUpdateSerializer

from django.http import HttpResponse, JsonResponse
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
from django.conf import settings
from django.core.files.base import ContentFile
from django.contrib.auth.hashers import make_password


from drf_spectacular.utils import extend_schema
from drf_spectacular.openapi import OpenApiParameter
from django.db.models.functions import TruncYear
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta, datetime

logger = logging.getLogger(__name__)


class DashboardAnalytics(BaseAPIView):
    def get(self, request):
        try:
            if request.user.role == "member":
                return Response(
                    {"detail": "You do not have permission to perform this action."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            organizations = Organization.objects.filter(
                created_by=request.user
            )

            # Count total members
            total_member_count = Member.objects.filter(
                department__organization__in=organizations
            ).distinct().count()

            # Count total recall messages
            total_recall_messages = RecallMessage.objects.filter(
                organization__in=organizations
            ).count()

            # Count total groups
            total_group_count = Group.objects.filter(
                created_by=request.user
            ).count()

            response_data = {
                "total_member_count": total_member_count,
                "total_group_count": total_group_count,
                "total_recall_messages": total_recall_messages,
            }

            return Response({"results": response_data}, status=status.HTTP_200_OK)

        except Exception as ex:
            logger.error("Something went wrong", exc_info=ex)
            raise APIException(detail=str(ex))


#  ---------------- Organization, Department & Member Viewset ------------------
class Organization_Viewset(BaseViewSet):
    serializer_class = OrganizationSerializer
    queryset = Organization.objects.select_related("created_by")

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(
                {"results": serializer.data}, status=status.HTTP_201_CREATED, headers=headers
            )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    @extend_schema(
        parameters=[
            OpenApiParameter('q', type=str, description='Search query'),
        ])
    def list(self, request, *args, **kwargs):
        try:
            q = request.GET.get("q")
            self.queryset = self.filter_queryset(self.get_queryset())
            if q:
                self.queryset = self.queryset = self.queryset.filter(
                    Q(name__icontains=q)
                    | Q(created_by__first_name__icontains=q)
                    | Q(created_by__last_name__icontains=q)
                    | Q(created_by__email__icontains=q)
                )
            if self.pagination:
                page = self.paginate_queryset(self.queryset)
                if page is not None:
                    serializer = self.get_serializer(page, many=True)
                    return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(self.queryset, many=True)
            return Response({"results": serializer.data})
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    def retrieve(self, request, *args, **kwargs):
        try:
            try:
                instance = self.queryset.get(id=self.kwargs['pk'])

                user = self.request.user
                if user.role == 'superadmin':
                    if instance.created_by != user:
                        return Response(
                            {"detail": "You are not allowed to see this organization."},
                            status=status.HTTP_403_FORBIDDEN,
                        )
                elif user.role in ['admin', 'editor', 'reader']:
                    if not instance.users.filter(pk=user.pk).exists():
                        return Response(
                            {"detail": "You are not allowed to see this organization."},
                            status=status.HTTP_403_FORBIDDEN,
                        )
                else:
                    return Response(
                        {"detail": "You do not have permission to perform this action."},
                        status=status.HTTP_403_FORBIDDEN,
                    )

                serializer = self.get_serializer(instance)
                return Response({"results": serializer.data})

            except Organization.DoesNotExist:
                return Response({"detail": "Object not found."},
                                status=status.HTTP_404_NOT_FOUND,
                                )
        except Exception as ex:
            logger.error("Something went wrong", exc_info=ex)
            raise APIException(detail=str(ex))

    @extend_schema(
        parameters=[
            OpenApiParameter('organization_id', type=int, description='Organization ID', required=True),
        ])
    @action(detail=False, methods=["get"])
    def users(self, request, *args, **kwargs):
        try:
            organization_id = request.GET.get("organization_id")

            # Retrieve the organization based on the provided organization_id
            organization = Organization.objects.get(id=organization_id)

            # Get the users associated with the organization
            users = organization.users.all()

            if self.pagination:
                page = self.paginate_queryset(users)
                if page is not None:
                    serializer = UserUpdateSerializer(page, many=True)
                    return self.get_paginated_response(serializer.data)

            serializer = UserUpdateSerializer(users, many=True)
            return Response({"results": serializer.data})
        except Organization.DoesNotExist:
            return Response({"detail": "Organization not found"}, status=404)
        except Exception as ex:
            logger.error("Something went wrong", exc_info=ex)
            raise APIException(detail=str(ex))


# Department API
@extend_schema(
    description="Department API",
)
class Department_Viewset(BaseViewSet):
    serializer_class = DepartmentSerializer
    queryset = Department.objects.select_related("created_by")

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(
                {
                    "detail": "Successfully created department.",
                    "results": serializer.data,
                },
                status=status.HTTP_201_CREATED,
                headers=headers,
            )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    @extend_schema(
        description="Department List API",
        parameters=[
            OpenApiParameter(
                name="parent_department",
                description="Parent Department ID to get the sub-department list",
                type=int,
            ),
            OpenApiParameter(
                name="organization",
                description="Organization ID to get the department list",
                type=int,
            ),
            OpenApiParameter(
                name='q',
                type=str,
                description='Search query'
                ),
        ],
    )
    def list(self, request, *args, **kwargs):
        try:
            parent_department = request.GET.get("parent_department")
            organization = request.GET.get("organization")
            q = request.GET.get("q")

            if parent_department:
                self.queryset = self.get_queryset().filter(
                    parent_department=parent_department
                )
            elif organization:
                self.queryset = self.get_queryset().filter(
                    organization=organization, parent_department__isnull=True
                )
            else:
                self.queryset = self.get_queryset().filter(
                    parent_department__isnull=True
                )

            if q:
                self.queryset = self.queryset.filter(
                    Q(name__icontains=q)
                    | Q(created_by__first_name__icontains=q)
                    | Q(created_by__last_name__icontains=q)
                    | Q(created_by__email__icontains=q)
                )

            if self.pagination:
                page = self.paginate_queryset(self.queryset)
                if page is not None:
                    serializer = self.get_serializer(page, many=True)
                    return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(self.queryset, many=True)
            return Response({"results": serializer.data})
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)


# Member API
class Member_Viewset(BaseViewSet):
    serializer_class = MemberSerializer
    queryset = Member.objects.filter()

    @extend_schema(
        description="Member List API",
        parameters=[
            OpenApiParameter(
                name="department",
                description="Department ID to get the members list",
                type=int,
                required=True
            ),
            OpenApiParameter('q', 
                type=str,
                description='Search query'
            ),
        ],
    )
    def list(self, request, *args, **kwargs):
        try:
            department = request.GET.get("department", None)
            if not department:
                return Response(
                    {"detail": "You must add department query parameter"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            
            try:
                department_instance = Department.objects.get(id=department)
            except Department.DoesNotExist:
                return Response(
                    {"detail": "Department does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            
            if department_instance.created_by == request.user:
                q = request.GET.get("q")
                self.queryset = self.get_queryset().filter(department__id=department)

                if q:
                    self.queryset = self.queryset.filter(
                        Q(first_name__icontains=q)
                        | Q(last_name__icontains=q)
                        | Q(email__icontains=q)
                        | Q(phone__icontains=q)
                    )

                if self.pagination:
                    page = self.paginate_queryset(self.queryset)
                    if page is not None:
                        serializer = self.get_serializer(page, many=True)
                        return self.get_paginated_response(serializer.data)

                serializer = self.get_serializer(self.queryset, many=True)
                return Response({"results": serializer.data})
            else:
                return Response(
                    {"detail": "You are not allowed to see members of this department"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    def get_queryset(self):
        user = self.request.user
        # Fetch departments owned by the user
        owned_departments = Department.objects.filter(created_by=user)
        # Fetch members associated with the owned departments
        queryset = Member.objects.filter(department__in=owned_departments)
        return queryset

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        user = self.request.user

        # Check if the user owns the department associated with the member
        if instance.department.created_by == user:
            serializer = self.get_serializer(instance)
            return Response({"results": serializer.data})
        else:
            return Response(
                {"detail": "You do not have permission to access this member."},
                status=status.HTTP_403_FORBIDDEN,
            )

    def create(self, request, *args, **kwargs):
        try:
            department_id = request.data.get("department")

            try:
                department_instance = Department.objects.get(id=department_id)
            except Department.DoesNotExist:
                return Response(
                    {"detail": "Department does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
           
            
            if department_instance.created_by == request.user:
                phone = request.data.get("phone")
                email = request.data.get("email")

                # Check if a member with the same phone number already exists
                if Member.objects.filter(
                    phone=phone, department=department_id
                ).exists():
                    return Response(
                        {"detail": "A member with this phone number already exists."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Check if a member with the same email already exists
                if Member.objects.filter(
                    email=email, department=department_id
                ).exists():
                    return Response(
                        {"detail": "A member with this email already exists."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                serializer = self.get_serializer(data=request.data)
                if serializer.is_valid():
                    if (
                        User.objects.filter(email=email).exists()
                        or User.objects.filter(phone=phone).exists()
                    ):
                        if User.objects.filter(email=email, phone=phone).exists():
                            serializer.save(
                                created_by=request.user, is_active=False)
                            
                            email_response = send_activation_code_for_accept_invite(
                                serializer.data["id"]
                            )

                            if  email_response:
                                return Response(
                                    {
                                        "detail": "Email sent to the member to accept invitation!",
                                        "results": serializer.data,
                                    },
                                    status=status.HTTP_201_CREATED,
                                )
                            else:
                                return Response(
                                    {"detail": "Something went wrong"},
                                    status=status.HTTP_400_BAD_REQUEST,
                                )
                        else:
                            return Response(
                                {
                                    "detail": "Email and Phone is being used different accounts!"
                                },
                                status=status.HTTP_400_BAD_REQUEST,
                            )
                    else:
                        serializer.save(
                            created_by=request.user, is_active=False)
                        
                        email_response = send_activation_code_for_signup(
                            serializer.data["id"]
                        )

                        if email_response:
                            return Response(
                                {
                                    "detail": "Email sent to the member with the signup link!",
                                    "results": serializer.data,
                                },
                                status=status.HTTP_201_CREATED,
                            )
                        else:
                            return Response(
                                {"detail": "Something went wrong"},
                                status=status.HTTP_400_BAD_REQUEST,
                            )
                else:
                    return Response(
                        serializer.errors, status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                return Response(
                    {
                        "detail": "You are not allowed to add members to this department."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)


    @extend_schema(
        request=MemberVerifyCodeSerializer,  # Define a serializer for the request data 
    )
    @action(detail=False, methods=["post"])
    def verify_code(self, request):
        try:
            member_id = request.data.get("id")
            code = request.data.get("code")

            if not code:
                return Response(
                    {"detail": "Code is required"}, status=status.HTTP_400_BAD_REQUEST
                )
            if not member_id:
                return Response(
                    {"detail": "Id is required"}, status=status.HTTP_400_BAD_REQUEST
                )

            try:
                member = Member.objects.get(id=member_id)
                if member.code == code:
                    return Response(
                        {"detail": "Code is correct!"}, status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        {"detail": "Incorrect code, please try again!"},
                        status=status.HTTP_404_NOT_FOUND,
                    )
            except Member.DoesNotExist:
                return Response(
                    {"detail": "Incorrect code, Please try again!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    @extend_schema(
        parameters=[
            OpenApiParameter('organization_id', type=int, description='Organization ID', required=True),
            OpenApiParameter('q', type=str, description='Search query'),
        ]
    )
    @action(detail=False, methods=["get"])
    def organization(self, request):
        try:
            organization_id = request.query_params.get("organization_id", None)
            q = request.query_params.get("q", None)

            if not organization_id:
                return Response(
                    {"detail": "Organization ID is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            members = Member.objects.filter(
                department__organization_id=organization_id)

            if q:
                members = members.filter(
                    Q(first_name__icontains=q)
                    | Q(last_name__icontains=q)
                    | Q(email__icontains=q)
                    | Q(phone__icontains=q)
                )

            # Paginate the queryset
            page = self.paginate_queryset(members)
            if page is not None:
                serializer = MemberSerializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = MemberSerializer(members, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Organization.DoesNotExist:
            return Response(
                {"detail": "Organization not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except Exception as ex:
            logger.error("Something went wrong", exc_info=ex)
            return Response(
                {"detail": "Internal Server Error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# Member User Signup View
class MemberUserSignupView(PublicAPIView):
    serializer_class = MemberUserSignupSerializer

    def post(self, request, *args, **kwargs):
        try:
            first_name = request.data.get("first_name")
            last_name = request.data.get("last_name")
            email = request.data.get("email")
            phone = request.data.get("phone")
            otp = request.data.get("otp")
            activation_code = request.data.get("activation_code")
            password = request.data.get("password")
            confirm_password = request.data.get("confirm_password")

            # Check if a user with the given email already exists
            if User.objects.filter(email=email).exists():
                return Response(
                    {"detail": "User with this email already exists"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if User.objects.filter(phone=phone).exists():
                return Response(
                    {"detail": "User with this phone already exists"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Check if password and confirm_password match
            if password != confirm_password:
                return Response(
                    {"detail": "Password and confirm password do not match"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                member = Member.objects.get(
                    email=email, activation_code=activation_code, code=otp
                )

                if member:
                    # Create User
                    hashed_password = make_password(password)
                    user = User.objects.create(
                        first_name=first_name,
                        last_name=last_name,
                        email=email.lower(),
                        username=email.lower(),
                        phone=phone,
                        password=hashed_password,
                        role="member",
                        is_phone_verified=True,
                        is_email_verified=True,
                        account_status="active",
                        invited_by=member.created_by,
                        is_member=True,
                    )

                    member.is_active = True
                    member.user = user
                    member.otp = None
                    member.save()

                return Response(
                    {"detail": "Account is Successfully Created!"},
                    status=status.HTTP_200_OK,
                )

            except Member.DoesNotExist:
                return Response(
                    {
                        "detail": "Member not found or activation code is incorrect or OTP is wrong!"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

class MemberInviteSendOTPView(PublicAPIView):
    serializer_class = MemberInviteSendOTPSerializer
    
    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get("email")  
            activation_code = request.data.get("activation_code")  
            try:   
    
                member = Member.objects.get(email=email, activation_code=activation_code)
                
            except Member.DoesNotExist:
                return Response(
                    {
                        "detail": "Member not found or activation code is incorrect or email is wrong!"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
            )
           
            mobile_resposnse = send_code(member.phone, member.id)
            if "cooldown" in mobile_resposnse:
                return Response({"detail":mobile_resposnse["cooldown"]}, status=status.HTTP_200_OK)
            if mobile_resposnse:
                return Response({"detail":"OTP Successfully send to user phone"}, status=status.HTTP_200_OK)
            else:
                return Response({"detail": "Something went wrong while sending otp"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as ex:
                logger.info("Something went wrong", exc_info=ex)
                raise APIException(detail=ex)            


# Member User Accept Invite View
class MemberUserAcceptInviteView(PublicAPIView):
    serializer_class = MemberUserAcceptInviteSerializer

    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get("email")
            phone = request.data.get("phone")
            otp = request.data.get("otp")
            activation_code = request.data.get("activation_code")

            try:
                member = Member.objects.get(
                    email=email, activation_code=activation_code
                    
                )

                if member:
                    # Create User
                    user = User.objects.get(email=email, phone=phone)
                    user.is_member = True
                    user.save()

                    member.is_active = True
                    member.user = user
                    # member.otp = None
                    member.save()

                return Response(
                    {"detail": "You're successfully added as a Member!"},
                    status=status.HTTP_200_OK,
                )

            except Member.DoesNotExist:
                return Response(
                    {
                        "detail": "Member not found or activation code is incorrect or OTP is wrong!"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            except User.DoesNotExist:
                return Response(
                    {"detail": "User Does not exist! Contact your admin"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)


#  ---------------- Export & Import Views ------------------


# Member Export View
class MemberExportView(BaseAPIView):
    @extend_schema(
        description="Member Export API",
        parameters=[
            OpenApiParameter(
                name="department",
                description="Department ID to export members",
                type=int,
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        try:
            if request.user.role == "member":
                return Response(
                    {"detail": "You do not have permission to perform this action."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            department = request.GET.get("department", None)
            if not department:
                return Response(
                    {"detail": "You must add department query parameter"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            department_instance = get_object_or_404(Department, id=department)
            if department_instance.created_by == request.user:
                queryset = Member.objects.all()

                q = request.GET.get("q")
                department = request.GET.get("department")
                if department:
                    queryset = queryset.filter(department__id=department)

                if q:
                    queryset = queryset.filter(
                        Q(name__icontains=q)
                        | Q(email__icontains=q)
                        | Q(phone__icontains=q)
                    )

                serializer = MemberSerializer(queryset, many=True)

                response = HttpResponse(content_type="text/csv")

                writer = csv.writer(response)
                writer.writerow(["Name", "Email", "Phone"])

                for member in serializer.data:
                    writer.writerow(
                        [
                            member["name"],
                            member["email"],
                            member["phone"],
                        ]
                    )

                response[
                    "Content-Disposition"
                ] = f'attachment; filename="{department_instance.name}_members.csv"'
                return response
            else:
                return Response(
                    {"detail": "You are not allowed to see members of this department"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)


# Download Dummy CSV
class DownloadDummyCSV(BaseAPIView):
    def get(self, request, *args, **kwargs):
        if request.user.role == "member":
            return Response(
                {"detail": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN,
            )

        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="dummy.csv"'

        writer = csv.writer(response)

        # Add your dummy data rows here
        dummy_data = [
            ["John Doe", "john@example.com", "+12345678905"],
            ["Jane Smith", "jane@example.com", "+19876543210"],
            # Add more rows as needed
        ]

        for row in dummy_data:
            writer.writerow(row)

        return response


# Member Import View
class MemberImportView(BaseAPIView):
    serializer_class = MemberImportSerializer

    def post(self, request, *args, **kwargs):
        serializer = MemberImportSerializer(data=request.data)
        if serializer.is_valid():
            csv_file = serializer.validated_data["csv_file"]
            department_id = serializer.validated_data["department_id"]
            decoded_file = csv_file.read().decode("utf-8")
            io_string = io.StringIO(decoded_file)
            csv_reader = csv.reader(io_string)

            department_instance = get_object_or_404(
                Department, id=department_id)
            if department_instance.created_by == request.user:
                # Skip header row
                next(csv_reader, None)

                created_count = 0
                skipped_count = 0

                for row in csv_reader:
                    department_id = department_id
                    name = row[0]
                    email = row[1]
                    phone = row[2]

                    if (
                        not Member.objects.filter(
                            email=email, department=department_instance
                        ).exists()
                        and not Member.objects.filter(
                            phone=phone, department=department_instance
                        ).exists()
                    ):
                        member = Member(
                            department=department_instance,
                            name=name,
                            email=email,
                            phone=phone,
                        )
                        member.save()
                        created_count += 1
                    else:
                        skipped_count += 1

                return Response(
                    {
                        "detail": f"CSV data imported. Created: {created_count}, Skipped (Duplicates): {skipped_count}"
                    },
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {
                        "detail": "You are not allowed to import members for this department"
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
        else:
            return Response({"detail": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


#  ---------------- Recalls ------------------


# Send Message For Organizations
@extend_schema(
    description="Send Either Departments or Organization in the Payload",
)
class SendOrganizationMessageView(BaseAPIView):
    serializer_class = SendOrganizationMessageSerializer
    permission_classes = [IsAdminOrSuperAdmin]

    def post(self, request, format=None):
        try:
            serializer = SendOrganizationMessageSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            message = serializer.validated_data.get("message")
            departments = serializer.validated_data.get("departments", [])
            organization = serializer.validated_data.get("organization")
            title = serializer.validated_data.get("title")
            priority = serializer.validated_data.get("priority")
            category = serializer.validated_data.get("category")

            if departments and organization:
                return Response(
                    {
                        "detail": "Payload is not correct, Send Either departments or Organization ID"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # We store all the contacts in here
            members = []
            department_list = []
            recall_type = ""

            if organization:
                recall_type = "organization"
                organization_instance = Organization.objects.get(
                    id=organization)
                organization = organization_instance
                if organization_instance.created_by != request.user:
                    return Response(
                        {"detail": "You're not the user of this organization"},
                        status=status.HTTP_403_FORBIDDEN,
                    )
                departments = Department.objects.filter(
                    organization=organization, is_recalled=False
                )
            else:
                recall_type = "departments"

                # If category is Polls, need to check if its recalled already else its for everyone
                if category == "polls":
                    departments = Department.objects.filter(
                        id__in=departments, is_recalled=False
                    )
                else:
                    departments = Department.objects.filter(id__in=departments)

            for department in departments:
                if department.created_by != request.user:
                    continue

                # Update the department_list
                department_list.append(department)

                # Store organization ID
                if not organization:
                    organization = department.organization

                # If category is Polls, need to check if its recalled already else its for everyone
                if category == "polls":
                    members += Member.objects.filter(
                        department=department, is_recalled=False
                    )
                else:
                    members += Member.objects.filter(department=department)

            if members:
                response = dialpad_send_message(
                    message,
                    members,
                    request.user,
                    organization,
                    department_list,
                    recall_type,
                    title,
                    priority,
                    category,
                )
                return Response(
                    {"detail": response["report"],
                        "response": response["message"]},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"detail": "No Members are present for sending Recall!"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        except ValidationError as e:
            field_name, error_message = serailizer_errors(e)
            return Response(
                {"detail": f"{field_name} - {error_message}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)


# Send Message For Departments
@extend_schema(
    description="Send Either Members or Department in the Payload",
)
class SendDepartmentMessageView(BaseAPIView):
    serializer_class = SendDepartmentMessageSerializer
    permission_classes = [IsAdminOrSuperAdmin]

    def post(self, request, format=None):
        try:
            serializer = SendDepartmentMessageSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            message = serializer.validated_data.get("message")
            members = serializer.validated_data.get("members", [])
            department = serializer.validated_data.get("department")
            title = serializer.validated_data.get("title")
            priority = serializer.validated_data.get("priority")
            category = serializer.validated_data.get("category")

            if department and members:
                return Response(
                    {
                        "detail": "Payload is not correct, Send Either Department or Members"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            organization = None  # Initialize organization variable
            department_list = []
            recall_type = ""

            if department:
                recall_type = "departments"
                department_instance = Department.objects.get(id=department)

                if department_instance.created_by != request.user:
                    return Response(
                        {"detail": "You're not the user of this department"},
                        status=status.HTTP_403_FORBIDDEN,
                    )

                # Retrieve the organization associated with the department
                organization = department_instance.organization

                # If category is Polls, need to check if its recalled already else its for everyone
                if category == "polls":
                    members = Member.objects.filter(
                        department=department, is_recalled=False
                    )
                else:
                    members = Member.objects.filter(department=department)

                department_list.append(department_instance)

            elif members:
                recall_type = "members"
                for member in members:
                    department_instance = member.department
                    department_list.append(department_instance)
                    organization = department_instance.organization
                    break

            else:
                return Response(
                    {"detail": "Invalid request, please try again!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if category == "polls":
                if organization.is_recalled == True:
                    return Response(
                        {
                            "detail": "You can not send recall for this Organization, please disable the previous polls recall!"
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                elif department_instance.is_recalled == True:
                    return Response(
                        {
                            "detail": "You can not send recall for this department, please disable the previous polls recall!"
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            else:
                response = dialpad_send_message(
                    message,
                    members,
                    request.user,
                    organization,
                    department_list,
                    recall_type,
                    title,
                    priority,
                    category,
                )
                return Response(
                    {"detail": response["report"],
                        "response": response["message"]},
                    status=status.HTTP_200_OK,
                )
        except ValidationError as e:
            field_name, error_message = serailizer_errors(e)
            return Response(
                {"detail": f"{field_name} - {error_message}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)


# Recall Message API
class RecallMessageViewset(BaseViewSet):
    queryset = RecallMessage.objects.filter()
    http_method_names = ["get", "put", "post", "delete"]

    def get_permissions(self):
        if self.action in [
            "list",
            "retrieve",
            "submit_response"
        ]:
            permission_classes = [IsAuthenticated]
        elif self.action in ["update"]:
            permission_classes = [IsAdminOrSuperAdminOrEditor]
        else:
            permission_classes = [IsAdminOrSuperAdmin]

        permission_classes += [IsActiveUser]

        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        if self.action == "create": 
            if "category" in self.request.data and self.request.data["category"] == 'poll_template':      
                return RecallMessageCreatePollTemplateSerializer
           
            return RecallMessageCreateSerializer
        elif self.action in ["retrieve", "list"]:
            if (self.request.user.role in ["superadmin", "admin", "editor", "reader"]):
                return RecallMessageDetailSerializerAdmin
            else:
                return RecallMessageDetailSerializer
        elif self.action == "update":
            return RecallMessageUpdateSerializer
        elif self.action == "create_poll":
            return RecallMessageWithPollCreateSerializer
        elif self.action == "create_alert":
            return RecallMessageWithAlertCreateSerializer
        elif self.action == "submit_response":
            return RecallResponseCreateSerializer
        else:
            return RecallMessageSerializer

    @extend_schema(
        description="Recall Message API",
        parameters=[
            OpenApiParameter(name="department",
                             description="Department ID", type=int),
            OpenApiParameter(
                name="organization", description="Organization ID", type=int
            ),
            OpenApiParameter(
                name="category", description="Category type", type=str),
        ],
    )
    def get_queryset(self):
        user = self.request.user
        self.queryset = self.queryset.select_related(
            "created_by", "organization")

        if self.request.user.role == "superadmin":
            self.queryset = self.queryset.filter(created_by=user).prefetch_related(
                "departments",
                "members",
                "acknowledged",
                "poll_choices",
                "poll_choices__members",
            ).order_by("-created_on")

        elif self.request.user.role == "admin":
            self.queryset = self.queryset.filter(Q(created_by=user.invited_by) | Q(created_by=user)).prefetch_related(
                "departments",
                "members",
                "acknowledged",
                "poll_choices",
                "poll_choices__members",
            ).order_by("-created_on")

        elif self.request.user.role == 'member':
            member_instances = Member.objects.filter(user=user)
            self.queryset = self.queryset.filter(members__in=member_instances).prefetch_related(
                "poll_choices"
            ).order_by("-created_on")

        return self.queryset.distinct()
    
    @extend_schema(
        parameters=[
            OpenApiParameter('organization', type=int, description='Filter by organization ID'),
            OpenApiParameter('department', type=int, description='Filter by department ID'),
            OpenApiParameter('category', type=str, description='Filter by recall category (alert, polls, alert_template, poll_template)'),
            OpenApiParameter('active', type=str, description='Filter by active recalls'),
            OpenApiParameter('interval', type=str, description='Filter by interval (hour, week, month)'),
            OpenApiParameter('recall_type', type=str, description='Filter by recall type (group_recalls, recalls)'),
            OpenApiParameter('q', type=str, description='Search query'),
        ],
      
    )
    def list(self, request, *args, **kwargs):
        try:
            organization = request.query_params.get("organization")
            department = request.query_params.get("department")
            category = request.query_params.get("category")
            active = request.query_params.get("active")
            filter_interval = request.query_params.get("interval")
            recall_type = request.query_params.get("recall_type")

            q = request.GET.get("q")

            if recall_type == "group_recalls":
                self.queryset = self.queryset.filter(
                    recall_type="group_recalls")

            if active == 'true':
                member_instances = Member.objects.filter(user=request.user)
                user = request.user
                if self.request.user.role == "superadmin":
                    if self.request.user.is_member:
                        member_instances = Member.objects.filter(user=user)
                        self.queryset = self.queryset.filter(
                            Q(created_by=user) | Q(
                                members__in=member_instances)
                        )
                    else:
                        self.queryset = self.queryset.filter(created_by=user)

                    self.queryset = self.queryset.prefetch_related(
                        "departments",
                        "members",
                        "acknowledged",
                        "poll_choices",
                        "poll_choices__members",
                    )

                self.queryset = self.queryset.filter(
                    Q(members__in=member_instances) &
                    ~Q(acknowledged__in=member_instances) &
                    Q(is_expired=False)
                ).distinct().order_by("-created_on")
            else:
                self.queryset = self.filter_queryset(self.get_queryset())

            if q:
                self.queryset = self.queryset.filter(
                    Q(message__icontains=q)
                    | Q(title__icontains=q)
                    | Q(created_by__first_name__icontains=q)
                    | Q(created_by__last_name__icontains=q)
                )

            # Filters for 1 hour, 1 week, and 1 month
            if filter_interval == "hour":
                filter_date = timezone.now() - timedelta(hours=1)
                self.queryset = self.queryset.filter(
                    created_on__gte=filter_date)
            elif filter_interval == "week":
                filter_date = timezone.now() - timedelta(weeks=1)
                self.queryset = self.queryset.filter(
                    created_on__gte=filter_date)
            elif filter_interval == "month":
                filter_date = timezone.now() - timedelta(weeks=4)
                self.queryset = self.queryset.filter(
                    created_on__gte=filter_date)

            if category and category != "all":
                if category == "templates":
                    self.queryset = self.queryset.filter(
                        category__in=["alert_template", "poll_template"]
                    )
                else:
                    self.queryset = self.queryset.filter(category=category)

            if organization:
                self.queryset = self.queryset.filter(organization=organization)
            elif department:
                self.queryset = self.queryset.filter(
                    departments__id=department)

            if self.pagination:
                page = self.paginate_queryset(self.queryset)
                if page is not None:
                    serializer = self.get_serializer(page, many=True)
                    return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(self.queryset, many=True)
            return Response({"results": serializer.data})
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    def update(self, request, *args, **kwargs):
        return Response(
            {"detail": "PUT method not allowed for now!"},
            status=status.HTTP_400_BAD_REQUEST,
        )
  
    def destroy(self, request, *args, **kwargs):
        try:
            instance = RecallMessage.objects.get(pk=kwargs.get('pk'))

            if (request.user == instance.created_by ) and (request.user.role == 'superadmin'):
                self.perform_destroy(instance)
                return Response({"results":"Successfully deleted"},status=status.HTTP_204_NO_CONTENT)

            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

        except RecallMessage.DoesNotExist:
            return Response({'detail': 'Not found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as ex:
            logger.error("Something went wrong", exc_info=ex)
            return Response({'detail': 'An error occurred while processing your request.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    @action(detail=True, methods=["put"])
    def mark_as_expired(self, request, pk=None):
        instance = self.get_object()

        # Assuming you want to restrict this action to the creator of the instance
        if instance.created_by != self.request.user:
            raise PermissionDenied(
                "You don't have permission to mark this object as expired."
            )

        # Update the is_expired field
        instance.is_expired = True
        instance.save()

        # Set is_recalled to False for all associated members and departments
        instance.members.all().update(is_recalled=False)
        instance.departments.all().update(is_recalled=False)

        serializer = self.get_serializer(instance)
        return Response(
            {"detail": "Successfully Ended the Recall"}, status=status.HTTP_200_OK
        )

    def perform_create(self, serializer):
        # Set the created_by field to the current user before saving
        serializer.save(created_by=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        message_category = serializer.validated_data.get("category")
        organization_id = serializer.validated_data.get("organization")

        try:
            organization_data = Organization.objects.get(id=organization_id.id)
            if organization_data.created_by != request.user:
                return Response(
                    {
                        "detail": "You are not allowed to perform operations on this organization."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Organization.DoesNotExist:
            raise ValidationError("Invalid organization ID provided.")

        # Check if the message_category is 'poll_template' or 'alert_template'
        if message_category in ["poll_template", "alert_template"]:
            self.perform_create(serializer)

        else:
            # Return a response indicating that the instance was not created
            return Response(
                {"detail": "Instance not created. Invalid message_category."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        headers = self.get_success_headers(serializer.data)
        return Response(
            {"detail": "Successfully Created!"},
            status=status.HTTP_201_CREATED,
            headers=headers,
        )

    @action(detail=False, methods=["post"])
    def create_poll(self, request, *args, **kwargs):
        try:
            messages_type = request.data.get("messages_type", "recalls")

            if (messages_type == "group_recalls"):
                group = Group.objects.get(id=request.data.get("group"))
                request.data["organization"] = group.organization.id
                request.data["departments"] = [
                    department.id for department in group.departments.all()]
                request.data["members"] = [
                    member.id for member in group.members.all()]
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            # Use the create method of the serializer, which includes creating poll choices
            self.perform_create(serializer)
            # Create a Notification for each member
            members = list(Member.objects.filter(
                id__in=serializer.data.get("members", [])))

            for member in members:
                if (member.user):
                    recall_message = RecallMessage.objects.get(id=serializer.data["id"])
                    Notification.objects.create(
                        user=member.user, message="You've received a new Poll!",recall_message=recall_message, type="poll")

            headers = self.get_success_headers(serializer.data)
            return Response({"detail": "Poll Successfully Created!", "results": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)
        except ValidationError as e:
            field_name, error_message = serailizer_errors(e)
            detail = f"{field_name} - {error_message}"
            if (field_name == "non_field_errors"):
                detail = f"{error_message}"
                return Response(
                    {"detail": detail},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response(
                {"detail": detail},
                status=status.HTTP_400_BAD_REQUEST,
            )

    @action(detail=False, methods=["post"])
    def create_alert(self, request, *args, **kwargs):
        try:
            messages_type = request.data.get("messages_type", "recalls")

            if (messages_type == "group_recalls"):
                group = Group.objects.get(id=request.data.get("group"))
                request.data["organization"] = group.organization.id
                request.data["departments"] = [
                    department.id for department in group.departments.all()]
                request.data["members"] = [
                    member.id for member in group.members.all()]
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            # Use the create method of the serializer, which includes creating poll choices
            self.perform_create(serializer)
            # Create a Notification for each member
            members = list(Member.objects.filter(
                id__in=serializer.data.get("members", [])))    
            for member in members:
                if (member.user):
                    recall_message = RecallMessage.objects.get(id=serializer.data["id"])
                    Notification.objects.create(
                        user=member.user, message="You've received a new Alert!", recall_message=recall_message, type="alert")

            headers = self.get_success_headers(serializer.data)
            return Response({"detail": "Alert Successfully Created!", "results": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)
        except ValidationError as e:
            field_name, error_message = serailizer_errors(e)
            detail = f"{field_name} - {error_message}"
            if (field_name == "non_field_errors"):
                detail = f"{error_message}"
                return Response(
                    {"detail": detail},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            return Response(
                {"detail": detail},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except ObjectDoesNotExist:
            return Response(
                {"detail": "Invalid data provided."}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as exception:
            logger.error("Something went wrong", exc_info=exception)
            return Response(
                {"detail": "Internal server error."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=False, methods=["post"])
    def submit_response(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            recall_message_id = serializer.validated_data.get(
                'recall_message_id')
            response_id = serializer.validated_data.get('response_id')
            acknowledged = serializer.validated_data.get('acknowledged')

            recall_message_instace = RecallMessage.objects.get(
                id=recall_message_id)
            category = recall_message_instace.category
            departments_of_recall_message = recall_message_instace.departments.all()

            member = Member.objects.get(
                user=request.user, department__in=departments_of_recall_message)

            present_members = recall_message_instace.members.all()

            if (member not in present_members):
                # Checking if member is in members list
                return Response({"response": "You're not allowed to respond on this recall"},
                                status=status.HTTP_400_BAD_REQUEST)
            elif (member in recall_message_instace.acknowledged.all()):
                # Checking if member member already responded
                raise serializers.ValidationError(
                    "You already responded to this recall")
            elif (recall_message_instace.is_expired):
                # Checking if recall is expired
                raise serializers.ValidationError(
                    "You cannot respond to this recall as it has expired.")

            if category == "alert":
                if acknowledged == True:
                    recall_message_instace.acknowledged.add(member)
                    #  mark notification as read
                    notification = Notification.objects.get(user=request.user, recall_message=recall_message_instace)
                    notification.is_read = True
                    notification.save()

                    return Response({"detail": "Recall Response Successfully Submited For Alert!"},
                                    status=status.HTTP_200_OK)
                else:
                    return Response({"detail": "Something went wrong!"}, status=status.HTTP_400_BAD_REQUEST)

            elif category == "polls":
                recall_message_poll_choice = RecallMessagePollChoice.objects.get(
                    id=response_id)

                # members_in_poll_choice = recall_message_poll_choice.members.all()

                recall_message_poll_choice.members.add(member)
                recall_message_poll_choice.votes += 1
                recall_message_instace.acknowledged.add(member)
                recall_message_poll_choice.save()

                #  mark notification as read
                notification = Notification.objects.get(user=request.user, recall_message=recall_message_instace)
                notification.is_read = True
                notification.save()

                return Response({"detail": "Response Successfully Submited For Poll!", }, status=status.HTTP_201_CREATED)

        except ValidationError as e:
            field_name, error_message = serailizer_errors(e)
            detail = f"{field_name} - {error_message}"
            if (field_name == "non_field_errors"):
                detail = f"{error_message}"
                return Response(
                    {"detail": detail},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response(
                {"detail": detail},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Member.DoesNotExist:
            return Response(
                {"detail": "You're not a member !"}, status=status.HTTP_400_BAD_REQUEST
            )
        except ObjectDoesNotExist:
            return Response(
                {"detail": "Invalid data provided."}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as exception:
            logger.error("Something went wrong", exc_info=exception)
            return Response(
                {"detail": "Internal server error."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# Polls Response
class RecallMessagePollChoiceUpdateView(BaseAPIView):
    queryset = RecallMessagePollChoice.objects.all()
    serializer_class = PollChoiceResponseSerializer

    def put(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            choice_text = serializer.validated_data.get("choice_text")
            recall_message = serializer.validated_data.get("recall_message")
            instance = RecallMessage.objects.get(id=recall_message)

            serializer.is_valid(raise_exception=True)

            user = self.request.user
            if user in instance.members:
                instance.votes += 1

            serializer.save()

            return Response({"detail": "Your response has been received"}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response(
                {"detail": "Invalid data provided."}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as ex:
            logger.error("Unexpected exception occurred", exc_info=ex)
            raise APIException(detail=ex)


# Recall Tab Cards Count View
class RecallCountViewSet(BaseViewSet):
    queryset = RecallMessage.objects.filter()
    http_method_names = ["get"]
    
    def get_permissions(self):
        permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def get_queryset(self):
        user = self.request.user
        
        self.queryset = self.queryset.all()
        if self.request.user.role == "superadmin":
            if(self.request.user.is_member):
                member_instances = Member.objects.filter(user=user)
                self.queryset = self.queryset.filter(   Q(members__in=member_instances) | Q(created_by=user)).order_by("-created_on")
            else:
                self.queryset = self.queryset.filter(created_by=user).all().order_by("-created_on")
            
        elif self.request.user.role == "admin":
            if(self.request.user.is_member):
                member_instances = Member.objects.filter(user=user)
                self.queryset = self.queryset.filter(Q(created_by=user.invited_by) | Q(created_by=user) | Q(members__in=member_instances)).order_by("-created_on") | self.queryset.filter(created_by=user).all().order_by("-created_on")
            else:
                self.queryset = self.queryset.filter(Q(created_by=user.invited_by) | Q(created_by=user)).all().order_by("-created_on")
            
        elif self.request.user.role == 'member':
            member_instances = Member.objects.filter(user=user)
            self.queryset = self.queryset.filter(members__in=member_instances).order_by("-created_on")

        return self.queryset

    @extend_schema(
        parameters=[
            OpenApiParameter('organization_id', type=int, description='Filter by organization ID'),
            OpenApiParameter('department_id', type=int, description='Filter by department ID'),
        ],
       
    )
    def list(self, request, *args, **kwargs):
        user = self.request.user
        organization_id = self.request.query_params.get('organization_id')
        department_id = self.request.query_params.get('department_id')

        if user.role == "superadmin":
            recall_messages = self.queryset.filter(created_by=user)
            total_groups = Group.objects.filter(
                created_by=request.user).count()
        elif user.role == "admin":
            recall_messages = self.queryset.filter( Q(created_by=request.user)| Q(created_by=user.invited_by))
            total_groups = Group.objects.filter(
                Q(created_by=request.user)| Q(created_by=user.invited_by)).count()
        else:
            recall_messages = self.queryset.filter(users__in=[user])
            total_groups = Group.objects.filter(users__in=[user]).count()

        if organization_id is not None:
            recall_messages = recall_messages.filter(
                organization__id=organization_id)
            total_groups = Group.objects.filter(
                organization__id=organization_id).count()

        if department_id is not None:
            recall_messages = recall_messages.filter(
                departments__id=department_id)
            total_groups = Group.objects.filter(
                departments__id=department_id).count()
            
    
        
        alerts_count = recall_messages.filter(category="alert").count()
        polls_count = recall_messages.filter(category="polls").count()

        res = {
            "total_group": total_groups,
            "total_recalls": recall_messages.count(),
            "total_alerts": alerts_count,
            "total_polls": polls_count,
        }
        return Response({"results": res}, status.HTTP_200_OK)

    @action(detail=False, methods=["get"])
    def alert_count(self, request):
        user = self.request.user
        if user.role == "superadmin":
            recall_messages = self.queryset.filter(created_by=user)
        else:
            recall_messages = self.queryset.filter(users__in=[user])
        alert_count = recall_messages.filter(category="alert").count()

        return Response(
            {
                "results": {
                    "total_alerts": alert_count,
                    "sent_alerts": 0,
                    "scedheuled_alerts": 0,
                }
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["get"])
    def poll_count(self, request):
        user = self.request.user
        if user.role == "superadmin":
            recall_messages = self.queryset.filter(created_by=user)
        else:
            recall_messages = self.queryset.filter(users__in=[user])
        poll_count = recall_messages.filter(category="polls").count()
        return Response(
            {
                "results": {
                    "total_polls": poll_count,
                    "sent_polls": 0,
                    "scedheuled_polls": 0,
                    "template_polls": 0,
                }
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["get"])
    def exercises_count(self, request):
        return Response(
            {
                "results": {
                    "total_exercises": 0,
                    "alert_exercises": 0,
                    "polls_exercises": 0,
                }
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["get"])
    def template_count(self, request):
        user = self.request.user
        recall_messages = self.queryset.filter(
            created_by=user) if user.role == "superadmin" else self.queryset.filter(users__in=[user])

        template_counts = recall_messages.values(
            'category').annotate(count=Count('category'))

        alert_template_count = next(
            (item['count'] for item in template_counts if item['category'] == 'alert_template'), 0)
        poll_template_count = next(
            (item['count'] for item in template_counts if item['category'] == 'poll_template'), 0)

        return Response(
            {
                "results": {
                    "total_templates": alert_template_count + poll_template_count,
                    "alert_templates": alert_template_count,
                    "poll_templates": poll_template_count,
                }
            },
            status=status.HTTP_200_OK,
        )


# Public Webhook For Dialpad
class WebhookView(PublicAPIView):
    authentication_classes = []
    serializer_class = DialpadWebhookSerializer

    def post(self, request, *args, **kwargs):
        # Print the request body
        print(request.data)

        response = request.data
        members = Member.objects.filter(phone=response["from_number"])
        for member in members:
            if member.is_recalled == True:
                recall_response = response["text_content"]
                latest_recall_message = (
                    RecallMessage.objects.filter(departments=member.department)
                    .order_by("-id")
                    .first()
                )
                RecallResponse.objects.create(
                    member=member,
                    response=recall_response,
                    recall_message=latest_recall_message,
                )

                member.is_recalled = False
                # member.department.is_recalled = False
                member.save()

        return Response(status=200)


# Public Webhook For Twilio
class TwilioWebhookView(PublicAPIView):
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        # Print the request body
        print(request.data)

        response = request.data
        return Response({"results": response})


#  ---------------- Groups & Hot Button Viewset ------------------
# Group APIs
@extend_schema(description="Group API")
class Group_Viewset(BaseViewSet):
    queryset = Group.objects.select_related(
        "created_by",
        "organization",
        "organization__created_by"
    ).prefetch_related(
        "members",
        "departments",
        "departments__created_by"
    )

    def get_serializer_class(self):
        if self.action == "create":
            return GroupCreateSerializer
        elif self.action == "update":
            return GroupUpdateSerializer
        else:
            return GroupSerializer

    @extend_schema(
        description="Create a new group",
        request=GroupCreateSerializer,  # Specify the request body serializer
        responses={
            201: {"description": "Successfully created group"},
            400: {"description": "Validation error occurred"},
            500: {"description": "Internal server error"},
        },
    )
    def group_create_and_update_validation(self, error):
        try:
            error_details = error.detail
            # Checking for nested serilizations
            field_name, error_list = list(error_details.keys())[
                0], list(error_details.values())[0]
            # First nesting to check for orginations
            if (isinstance(error_list, dict)):
                field_name, error_list = list(error_list.keys())[
                    0], list(error_list.values())[0]
                error_list = error_list[0]
                # Second nesting to check for depatrments
                if (isinstance(error_list, dict)):
                    field_name, error_list = list(error_list.keys())[
                        0], list(error_list.values())[0]
                    error_list = error_list[0]
                    # Third nesting to check for sub depatrments
                    if (isinstance(error_list, dict)):
                        field_name, error_list = list(error_list.keys())[
                            0], list(error_list.values())[0]
            # Handling non fields errors
            if field_name == "non_field_errors":
                detail = str(error_list[0]) if error_list else ''
                return Response(
                    {"detail": detail},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # Checking if final error is a list
            if (isinstance(error_list, list)):
                error_list = error_list[0].replace("This ", "")
            # if final error is not list then it is a string
            else:
                error_list = error_list.replace("This ", "")
            return Response(
                {"detail": str(field_name) + " "+str(error_list)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except:
            return Response(
                {"detail": "Invalid data provided !"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save(created_by=self.request.user)
            headers = self.get_success_headers(request.data)
            return Response(
                {
                    "detail": "Successfully created group.",
                },
                status=status.HTTP_201_CREATED,
                headers=headers,
            )
        except ValidationError as e:
            return self.group_create_and_update_validation(e)
        except ObjectDoesNotExist:
            return Response(
                {"detail": "Invalid data provided."}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as exception:
            logger.error("Something went wrong", exc_info=exception)
            return Response(
                {"detail": "Internal server error."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='group_id',
                type=int,
                description='ID of the group',
                # required=True,
                location=OpenApiParameter.QUERY
            ),
        ]  
    )
    @action(detail=False, methods=["get"])
    def members(self, request, *args, **kwargs):
        try:
            group_id = request.GET.get("group_id", None)
            if group_id is None:
                return Response({"detail": "group_id is required"})
            group = self.queryset.get(id=group_id)
            if group:
                members = group.members.all()

            if self.pagination:
                page = self.paginate_queryset(members)
                if page is not None:
                    serializer = MemberSerializer(page, many=True)
                    return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(self.queryset, many=True)
            return Response({"results": serializer.data})
        except Group.DoesNotExist:
            return Response(
                {"detail": "Group Does not Exist!"}, status=status.HTTP_404_NOT_FOUND
            )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    @extend_schema(
        description="Group List API",
        parameters=[
            OpenApiParameter(
                name="department",
                description="Department ID to get the group info",
                type=int,
            ),
            OpenApiParameter(
                name="organization",
                description="Organization ID to get the group info",
                type=int,
            ),
            OpenApiParameter(
                name="q", description="To search group using q", type=str),
        ],
    )
    def list(self, request, *args, **kwargs):
        try:
            department = request.GET.get("department")
            organization = request.GET.get("organization")
            q = request.GET.get("q")

            if department:
                self.queryset = self.get_queryset().filter(
                    departments=department, created_by=self.request.user
                )
            elif organization:
                self.queryset = self.get_queryset().filter(
                    organizations=organization,
                    created_by=self.request.user,
                    departments__isnull=True,
                )
            else:
                self.queryset = self.get_queryset().filter(created_by=self.request.user)

            if q:
                self.queryset = self.queryset.filter(name__icontains=q)

            # Use distinct() to get unique results instead of a set
            total_members_count = self.queryset.values(
                'members').distinct().count()

            if self.pagination:
                page = self.paginate_queryset(self.queryset)
                if page is not None:
                    serializer = self.get_serializer(page, many=True)
                    response = self.get_paginated_response(serializer.data)
                    response.data["total_members_count"] = total_members_count
                    return response
            serializer = self.get_serializer(self.queryset, many=True)
            return Response(serializer.data)
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    def retrieve(self, request, *args, **kwargs):
        try:
            return super().retrieve(request, *args, **kwargs)
        except Group.DoesNotExist:
            return Response(
                {"detail": "Group Does not Exist!"}, status=status.HTTP_404_NOT_FOUND
            )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    def update(self, request, pk=None, *args, **kwargs):
        try:
            instance = self.get_object()
            if instance.created_by != self.request.user:
                raise PermissionDenied(
                    "You don't have permission to update this object."
                )
            serializer = self.get_serializer(instance, data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"detail": "Sucessfully updated!"})
        except Group.DoesNotExist:
            return Response(
                {"detail": "Group Does not Exist!"}, status=status.HTTP_404_NOT_FOUND
            )
        except ValidationError as e:
            return self.group_create_and_update_validation(e)
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    def partial_update(self, request, pk=None, *args, **kwargs):
        try:
            instance = self.get_object()
            if instance.created_by != self.request.user:
                raise PermissionDenied(
                    "You don't have permission to update this object."
                )
            serializer = self.get_serializer(
                instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"detail": "Sucessfully updated!"})
        except Group.DoesNotExist:
            return Response(
                {"detail": "Group Does not Exist!"}, status=status.HTTP_404_NOT_FOUND
            )
        except ValidationError as e:
            return self.group_create_and_update_validation(e)
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    def destroy(self, request, pk=None, *args, **kwargs):
        try:
            instance = self.get_object()
            if instance.created_by != self.request.user:
                raise PermissionDenied(
                    "You don't have permission to delete this object."
                )
            instance.delete()
            return Response(
                {"detail": "Successfully deleted"}, status=status.HTTP_204_NO_CONTENT
            )
        except Exception as ex:
            raise APIException(detail=ex)


class InviteAdminToGroup(BaseAPIView):
    @extend_schema(
        description="Invite Admin",
        request=InviteGroupAdminSerializer,  # Specify the request body serializer
        responses={
            200: {"description": "Invite send successfully"},
            400: {"description": "Validation error occurred"},
            500: {"description": "Internal server error"},
        },
    )
    def post(self, request, format=None):
        try:
            serializer = InviteGroupAdminSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            response = send_activation_code_for_accept_invite_admin(
                serializer.data["admin_id"],
                serializer.data["group_id"],
            )

            return Response(
                {"detail": "Invite send successfully"},
                status=status.HTTP_200_OK,
            )
        except ValidationError as e:
            field_name, error_message = serailizer_errors(e)
            detail = f"{field_name} - {error_message}"
            if (field_name == "non_field_errors"):
                detail = f"{error_message}"
                return Response(
                    {"detail": detail},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response(
                {"detail": detail},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    @extend_schema(
        description="Get details for activation token and group ID",
        parameters=[
            OpenApiParameter(
                name='activation_token',
                type=str,
                description='Activation token for the group',
                location=OpenApiParameter.QUERY
            ),
            OpenApiParameter(
                name='group_id',
                type=int,
                description='ID of the group',
                location=OpenApiParameter.QUERY
            ),
        ]   
    )
    def get(self, request, *args, **kwargs):
        try:
            activation_token = request.GET.get("activation_token", None)
            group_id = request.GET.get("group", None)
            user = request.user

            if not activation_token or not group_id:
                return Response(
                    {"detail": "Invalid data"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            group = Group.objects.get(id=group_id)

            if group.admin:
                return Response(
                    {"detail": "Invitation already accepted"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            elif not (group.activation_token):
                return Response(
                    {"detail": "No activation token found"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if group.activation_token == activation_token:
                group.admin = user
                group.save()

            return Response(
                {
                    "detail": "Invitation accepted successfully",
                },
                status=status.HTTP_200_OK,
            )

        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)


class Group_CountView(BaseAPIView):
    def get(self, request):
        try:
            user = self.request.user
            try:
                if user.role == "superadmin":
                    groups = Group.objects.filter(created_by=user)
                elif user.role == "member":
                    return Response(
                        {"detail": "You do not have permission to perform this action."},
                        status=status.HTTP_403_FORBIDDEN,
                    )
                else:
                    groups = Group.objects.filter(admin=user)

            except Group.DoesNotExist:
                return Response({"detail": "Group not found"}, status=status.HTTP_404_NOT_FOUND)

            unique_members = set()
            for group in groups:
                unique_members.update(
                    group.members.values_list("id", flat=True))
            members_count = len(unique_members)

            return Response(
                {"results": {"group_count": len(
                    groups), "members_count": members_count}},
                status=status.HTTP_200_OK,
            )

        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)


class Group_Activity(BaseAPIView):

    @extend_schema(
        parameters=[OpenApiParameter('group_id', type=int, description='ID of the group', required=True)],
      
    )
    def get(self, request):
        try:
            user = self.request.user
            group_id = self.request.query_params.get('group_id')

            if group_id is None:
                return Response({"detail": "group_id is required"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                if user.role == "superadmin":
                    group = Group.objects.get(created_by=user, id=group_id)
                elif user.role == "member":
                    return Response(
                        {"detail": "You do not have permission to perform this action."},
                        status=status.HTTP_403_FORBIDDEN,
                    )
                else:
                    group = Group.objects.get(admin=user, id=group_id)
            except Group.DoesNotExist:
                return Response({"detail": "Group not found"}, status=status.HTTP_404_NOT_FOUND)

            member_count = group.members.count()
            # Optimize the queries using annotate
            recall_counts = RecallMessage.objects.filter(
                group=group).values('category').annotate(count=Count('id'))

            response = {
                "members_count": member_count,
                "alert_count": next((count['count'] for count in recall_counts if count['category'] == 'alert'), 0),
                "poll_count": next((count['count'] for count in recall_counts if count['category'] == 'polls'), 0),
            }

            return Response({"results": response},
                            status=status.HTTP_200_OK,
                            )

        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)


# Hot Buttons
class HotButton_Viewset(BaseViewSet):
    serializer_class = HotButtonSerializer
    queryset = HotButton.objects.select_related("created_by")

    def get_permissions(self):
        if self.action in [
            "list",
            "retrieve",
            "code_status"
        ]:
            permission_classes = [IsAuthenticated]
        elif self.action in ["update"]:
            permission_classes = [IsAdminOrSuperAdminOrEditor]
        else:
            permission_classes = [IsAdminOrSuperAdmin]

        permission_classes += [IsActiveUser]

        return [permission() for permission in permission_classes]

    def get_queryset(self):
        is_available_for_members = self.request.query_params.get(
            "is_available_for_members", None)
        is_show = self.request.query_params.get("is_show", None)
        queryset = HotButton.objects.select_related("created_by")

        # Filter objects based on the user (current user)
        if self.request.user.role == "member":
            queryset = queryset.filter(
                created_by=self.request.user.invited_by, is_available_for_members=True
            )
        elif self.request.user.role == "superadmin":
            queryset = queryset.filter(created_by=self.request.user)
        elif self.request.user.role == "admin":
            queryset = queryset.filter(Q(created_by=self.request.user.invited_by) | Q(created_by=self.request.user))
        else:
            queryset = queryset.filter(created_by=self.request.user.invited_by)

        # Filter to get specfic data
        if is_available_for_members:
            queryset = queryset.filter(
                is_available_for_members=is_available_for_members)
        if is_show:
            queryset = queryset.filter(is_show=is_show)

        # Sorting based on created_on
        return queryset.filter().order_by("-created_on")

    def perform_create(self, serializer):
        user = self.request.user

        if HotButton.objects.filter(created_by=user, is_show=True).count() >= 8:
            serializer.validated_data["is_show"] = False
        serializer.save(created_by=user)

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(
                {"detail": "Hot Button Successfully Created!",
                    "result": serializer.data},
                status=status.HTTP_201_CREATED,
                headers=headers,
            )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    def list(self, request, *args, **kwargs):
        try:
            self.queryset = self.filter_queryset(self.get_queryset())

            if self.pagination:
                page = self.paginate_queryset(self.queryset)
                if page is not None:
                    serializer = self.get_serializer(page, many=True)
                    return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(self.queryset, many=True)
            if serializer.data:
                return Response(serializer.data[0])
            else:
                return Response({})
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    @action(detail=False, methods=["post"])
    def set_code(self, request):
        user = request.user
        code = request.data.get("code", None)
        if code == None:
            return Response(
                {"detail": "Code is Required for Proceeding."}, status=status.HTTP_400_BAD_REQUEST
            )

        if len(code) != 6:
            return Response(
                {"detail": "Code Length Should Be Exectly Six Digits."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.code = code
        user.save()
        return Response(
            {"detail": "Code Successfully Created!"}, status=status.HTTP_201_CREATED
        )

    @action(detail=False, methods=["post"])
    def reset_code(self, request):
        user = request.user
        code = request.data.get("code")
        otp = request.data.get("otp")

        if otp:
            if otp != user.otp:
                return Response(
                    {"detail": "OTP Not Matched."}, status=status.HTTP_403_FORBIDDEN
                )
            if code == None:
                return Response(
                    {"detail": "Code is Required for Proceeding."}, status=status.HTTP_400_BAD_REQUEST
                )
            if len(code) != 6:
                return Response(
                    {"detail": "Code Length Should Be Exectly Six Digits."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            user.code = code
            user.save()
            return Response(
                {"detail": "Code Successfully Reset!"}, status=status.HTTP_200_OK
            )

        else:
            response = send_email_phone_otp(user)
            if response == "Success":
                return Response(
                    {
                        "detail": "OTP sent successfully! Please check your email and phone."
                    },
                    status=status.HTTP_200_OK,
                )
            elif response["by_email"] == "Success":
                return Response(
                    {"detail": "OTP sent successfully! Please check your email"},
                    status=status.HTTP_200_OK,
                )
            elif response["by_phone"] == "Success":
                return Response(
                    {"detail": "OTP sent successfully! Please check your phone"},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"detail": "Something went wrong while sending otp"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

    @action(detail=False, methods=["get"])
    def code_status(self, request):
        user = request.user
        if user.code == None:
            return Response({"results": False})
        else:
            return Response({"results": True})

    @action(detail=False, methods=["put"])
    def update_is_show(self, request):
        try:
            payload = request.data

            if not isinstance(payload, list):
                return Response(
                    {"detail": "Invalid input. Payload should be a list of objects."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            hot_button_ids = []
            is_show_values = {}
            display_order_values = {}
            true_count = 0

            for item in payload:
                hot_button_id = item.get("id")
                is_show = item.get("is_show")
                display_order = item.get("display_order", None)
                if is_show:
                    true_count += 1

                if hot_button_id is not None and isinstance(is_show, bool):
                    hot_button_ids.append(hot_button_id)
                    is_show_values[hot_button_id] = is_show

                if display_order is not None:
                    display_order_values[hot_button_id] = display_order

            if not hot_button_ids:
                return Response(
                    {
                        "detail": "Invalid input. No valid updates found in the payload."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if true_count > 8:
                return Response(
                    {"detail": "You can show only 8 hot buttons."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if len(display_order_values) > 8:
                return Response(
                    {"detail": "You can order only 8 hot buttons."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            hot_buttons = HotButton.objects.filter(
                id__in=hot_button_ids, created_by=self.request.user
            )

            for hot_button in hot_buttons:
                hot_button.is_show = is_show_values.get(
                    hot_button.id, hot_button.is_show
                )
                hot_button.display_order = display_order_values.get(
                    hot_button.id, hot_button.display_order
                )
                hot_button.save()

            HotButton.objects.filter(created_by=self.request.user).exclude(id__in=hot_button_ids).update(
                is_show=False
            )  # set is_show false to all other object

            return Response(
                {"detail": "Hot Button Configurations Updated Successfully"},
                status=status.HTTP_200_OK,
            )
        except Exception as ex:
            logger.error("Something went wrong", exc_info=ex)
            return Response(
                {"detail": "An error occurred while updating HotButton"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=False, methods=["put"])
    def update_hotbutton_for_members(self, request):
        serializer = HotButtonUpdateSerializer(data=request.data)
        if serializer.is_valid():
            hot_button_id = serializer.validated_data.get("hot_button_id")
            try:
                if hot_button_id is None:
                    return Response({"detail": "hot_button_id is required"}, status=status.HTTP_404_NOT_FOUND)
                hotbutton = HotButton.objects.get(id=hot_button_id)
            except HotButton.DoesNotExist:
                return Response({"detail": "HotButton not found"}, status=status.HTTP_404_NOT_FOUND)

            hotbutton.is_available_for_members = not hotbutton.is_available_for_members
            hotbutton.save()
            if hotbutton.is_available_for_members:
                return Response({"detail": f"HotButton is enabled for Members", "results": {"is_available_for_members": True}}, status=status.HTTP_200_OK)
            else:
                return Response({"detail": f"HotButton is disabled for Members", "results": {"is_available_for_members": False}}, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "Invalid data provided"}, status=status.HTTP_400_BAD_REQUEST)


# Send Hot Button Message API
class SendHotButtonMessage(BaseAPIView):
    serializer_class = SendHotButtonMessageSerializer

    def post(self, request):
        try:
            user = request.user
            code = request.data.get(("code"))

            if user.code == None:
                return Response(
                    {
                        "detail": "To send a hot button alert you need to set your code first"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            else:
                if code == None:
                    return Response(
                        {"detail": "Code is required!"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                if code != user.code:
                    return Response(
                        {"detail": "Code not matched!"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                hot_button_id = request.data.get("hot_button_id", None)
                if hot_button_id:
                    hot_button = HotButton.objects.get(id=hot_button_id)
                    if hot_button.created_by == request.user or (request.user.role in ["member", "admin", "editor", "reader"] and request.user.invited_by == hot_button.created_by):
                        # Send message to all the contacts
                        response = send_hot_button_message(hot_button)
                        return Response(response)
                    else:
                        return Response(
                            {"detail": "You are not allowed perform this action"},
                            status=status.HTTP_403_FORBIDDEN,
                        )
                else:
                    return Response(
                        {"detail": "Please provide hot button id"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

        except HotButton.DoesNotExist:
            return Response(
                {"detail": "Hot Button does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)


#  ---------------- Brand ------------------
# Brand API
class BrandViewSet(BaseViewSet):
    queryset = Brand.objects.all()
    serializer_class = BrandSerializer
    pagination_class = None

    def get_queryset(self):
        # Filter objects based on the user (current user)
        user = self.request.user
        if self.request.user.role == "superadmin":
            return self.queryset.filter(created_by=user)
        elif self.request.user.role == 'member':
            return self.queryset.filter(created_by=user.invited_by)
        else:
            organization = Organization.objects.filter(
                users__in=[user]).first()
            return self.queryset.filter(created_by=organization.created_by)

    def get_permissions(self):
        if self.action in ["list"]:
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [IsSuperAdmin]

        permission_classes += [IsActiveUser]
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        user = self.request.user
        try:
            # Attempt to get the existing Brand instance for the user
            existing_brand = Brand.objects.get(created_by=user)
            # If the instance exists, update it
            serializer = BrandSerializer(
                existing_brand, data=self.request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save(created_by=user)
        except Brand.DoesNotExist:
            # If the instance doesn't exist, create a new one
            serializer.save(created_by=user)
        except IntegrityError:
            # Handle other IntegrityError scenarios
            raise APIException(
                detail="Integrity error occurred while creating or updating the Brand."
            )

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(
                serializer.data, status=status.HTTP_201_CREATED, headers=headers
            )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)

    def list(self, request, *args, **kwargs):
        try:
            self.queryset = self.filter_queryset(self.get_queryset())

            if self.pagination:
                page = self.paginate_queryset(self.queryset)
                if page is not None:
                    serializer = self.get_serializer(page, many=True)
                    return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(self.queryset, many=True)
            if serializer.data:
                return Response(serializer.data[0])
            else:
                return Response({})
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)
        
    @extend_schema(
        request=None   
    )
    @action(detail=False, methods=["put"])
    def reset_brand(self, request):
        try:
            default_logo_url = settings.DEFAULT_LOGO_URL
            brand = Brand.objects.get(created_by=request.user)
            brand.name = "Total Recall"
            brand.color = "#072C50"
            # Fetch the image from the URL
            response = requests.get(default_logo_url)
            if response.status_code == 200:
                # Update the logo attribute
                logo_name = default_logo_url.split("/")[-1]
                brand.logo.save(logo_name, ContentFile(
                    response.content), save=True)

                return Response(
                    {"detail": "Successfully Updated!"}, status=status.HTTP_200_OK
                )
            else:
                # Handle the case where the logo URL couldn't be fetched
                return Response(
                    {"detail": "Failed to fetch the logo from the URL."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            
        except Brand.DoesNotExist:
            return Response(
                {"detail": "Brand not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)


#  ---------------- Salesforce ------------------


# Salesforce Ticket API
class SalesforceTicketAPIView(PublicAPIView):
    serializer_class = SalesforceTicketSerializer
    queryset = SalesforceTickets.objects.all()

    def post(self, request):
        try:    
            is_authenticated = self.request.user.is_authenticated
            
            serializer = SalesforceTicketSerializer(data=request.data, context={'request': request})
            serializer.is_valid(raise_exception=True)
            ticket_instance = serializer.save()
         
            if(is_authenticated):
                ticket_instance.created_by = request.user
                
            token = get_salesforce_token()
            response = create_salesforce_ticket(token, ticket_instance, serializer, request=request)
            
            
            if response.status_code == 200:
                id = response.json()["compositeResponse"][0]['body']['id']
                for file in request.FILES.getlist('file'):
                    file_model = TicketFile.objects.create(file=file)
                    ticket_instance.files.add(file_model)
                ticket_instance.ticket_id = id
                ticket_instance.save()
                
                
                return Response(
                    {
                        "detail": "Your ticket was submitted Successfully",
                        "salesforce_response": response.content,
                    },
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {"detail": response.json()[0]["message"]},
                    status=response.status_code,
                )
        except ValidationError as e:
            field_name, error_message = serailizer_errors(e)
            return Response(
                {"detail": f"{field_name} - {error_message}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except APIException as api_exception:
            # Handle APIException specifically
            logger.error("APIException occurred", exc_info=api_exception)
            return Response(
                {"detail": str(api_exception)}, status=api_exception.status_code
            )

        except Exception as ex:
            logger.error("Unexpected exception occurred", exc_info=ex)
            raise APIException(detail=ex)


class SalesforceTicketDetailAPIView(BaseAPIView):
    serializer_class = SalesforceTicketSerializer
    queryset = SalesforceTickets.objects.all()
    
    def get_queryset(self):
        user = self.request.user
        is_authenticated = self.request.user.is_authenticated
        record_type_id= self.request.query_params.get("record_type_id")
        
        if(is_authenticated):
            self.queryset = self.queryset.filter(created_by=user)
        if(record_type_id):
            self.queryset = self.queryset.filter(record_type_id = record_type_id)
            
        return self.queryset.filter(ticket_id_isnull=False)

    def get_tickets_from_salesforce(self,data):
        id_list = [i.ticket_id for i in data if i.ticket_id is not None]
        token = get_salesforce_token()
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "authorization": f"Bearer {token}"
        }
        if(len(id_list) != 1):
            ids = str(tuple(id_list))
        else:
            ids = f"('{id_list[0]}')"
    
        url = f"https://totalrecallsafety.my.salesforce.com/services/data/v59.0/query?q=SELECT Id,Status FROM Case WHERE Id IN {ids}"
        response = requests.get(url, headers=headers)
        
        return response.json()
        
    def get(self, request):
        try:
            page = self.paginate_queryset(self.queryset,request=request)
            serializer = SalesforceTicketSerializer(page, many=True)
            raw_json = json.dumps(serializer.data)
            datas = json.loads(raw_json)
            
            
            
            #Getting Data From Salesforce
            tickets = self.get_tickets_from_salesforce(page)["records"]
            
            #Creating Dict Of Id And Status
            status = dict()
            for ticket in tickets:
                status[ticket['Id']] = ticket["Status"]
                
            #Adding Status In Data
            results = []
            for data in datas:
                try:
                    id = data['ticket_id']
                    data['status'] = status[id]
                    results.append(data)
                except:
                    pass
                
            return self.get_paginated_response(results)
        except Exception as ex:
            logger.error("Unexpected exception occurred", exc_info=ex)
            raise APIException(detail=ex)

# Salesforce Lead API
class SalesforceLeadView(PublicAPIView):
    serializer_class = SalesforceLeadSerializer

    def post(self, request):
        try:
            serializer = SalesforceLeadSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            token = get_salesforce_token()
            response = create_salesforce_lead(
                token, serializer, "Landing page")
            if response.status_code == 201:
                waitlist_confirmation_email(serializer)
                return Response(
                    {
                        "detail": "We've received your email, thanks for joining the waitlist!",
                        "salesforce_response": response.content,
                    },
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {"detail": response.json()[0]["message"]},
                    status=response.status_code,
                )
        except ValidationError as e:
            field_name, error_message = serailizer_errors(e)
            return Response(
                {"detail": f"{field_name} - {error_message}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except APIException as api_exception:
            # Handle APIException specifically
            logger.error("APIException occurred", exc_info=api_exception)
            return Response(
                {"detail": str(api_exception)}, status=api_exception.status_code
            )

        except Exception as ex:
            logger.error("Unexpected exception occurred", exc_info=ex)
            raise APIException(detail=ex)



# Weather API
class WeatherAPI_View(BaseAPIView):
    @extend_schema(parameters=[
        OpenApiParameter('zip', type=int, description='Filter by ZIP code'),
        OpenApiParameter('zone', type=float, description='Filter by zone'),
        OpenApiParameter('zip_lat', type=float, description='Filter by ZIP code latitude'),
        OpenApiParameter('zip_lon', type=float, description='Filter by ZIP code longitude'),
        OpenApiParameter('county', type=str, description='Filter by county'),
        OpenApiParameter('county_lat', type=float, description='Filter by county latitude'),
        OpenApiParameter('county_lon', type=float, description='Filter by county longitude'),
    ])
    def get(self, request):
        filters = Q()
        query_params = [
            "zip",
            "zone",
            "zip_lat",
            "zip_lon",
            "county",
            "county_lat",
            "county_lon",
        ]

        for param in query_params:
            value = request.query_params.get(param)
            if value:
                filters &= Q(**{param: value})

        queryset = WeatherAlerts.objects.using("weather_api").filter(filters)
        page = self.paginate_queryset(queryset, self.request)

        if page is not None:
            serializer = WeatherAlertsSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = WeatherAlertsSerializer(queryset, many=True)
        return Response({"detail": serializer.data}, status=status.HTTP_200_OK)


# Checklist API
class ChecklistViewset(BaseViewSet):
    serializer_class = ChecklistSerializer
    queryset = Checklist.objects.select_related("created_by")

    def create(self, request, *args, **kwargs):
        checklist_data = request.data.get("checklist", [])
        title = request.data.get("title", "")

        if not title:
            return Response(
                {"detail": "title field is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not checklist_data or all(item == "" for item in checklist_data):
            return Response(
                {"detail": "checklist field may not be blank."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response({"detail": serializer.data}, status=status.HTTP_201_CREATED)
    


    @action(detail=False, methods=["get"])
    def checklist_count(self, request):
        user = self.request.user
        if user.role == "superadmin":
            checklist = self.queryset.filter(created_by=user)
        elif user.role == "admin":
            checklist = self.queryset.filter(Q(created_by=user.invited_by) | Q(created_by=user))
        else:
            checklist = self.queryset.filter(users__in=[user])

        checklist_count = checklist.count()
        return Response(
            {"detail": {"total_checklist": checklist_count}}, status=status.HTTP_200_OK
        )


# -------------------- ChartsViewSet-----------------------

class ChartViewset(BaseViewSet):
    queryset = RecallMessage.objects.all()
    http_method_names = ["get"]
    @extend_schema(exclude=True)
    def list(self, request, *args, **kwargs):
        raise MethodNotAllowed("get")
    
    @extend_schema(exclude=True)
    def retrieve(self, request, *args, **kwargs):
        pass

    def http_method_not_allowed(self, request, *args, **kwargs):
        raise MethodNotAllowed(request.method)
    
    @extend_schema(parameters=[OpenApiParameter('year', type=int, description='Filter by year')])
    @action(detail=False, methods=["get"])
    def recalls(self, request):
        user = self.request.user
        year = request.query_params.get('year', None)

        if user.role == 'superadmin':
            queryset = RecallMessage.objects.filter(created_by=request.user)
        elif request.user.role == "member":
            return Response(
                {"detail": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN,
            )
        else:
            queryset = RecallMessage.objects.filter(
                created_by=request.user.invited_by)

        if year:
            queryset = queryset.filter(created_on__year=year)

        data = queryset.annotate(year=TruncYear('created_on')).values(
            'year', 'category').annotate(count=Count('id'))

        chart_data = []

        categories = ['alert', 'polls']
        years = set(item['year'].year for item in data)

        for year in years:
            year_data = {'year': str(year)}

            for category in categories:
                count = next((item['count'] for item in data if item['year'].year ==
                             year and item['category'] == category), 0)
                year_data[category] = count

            chart_data.append(year_data)

        return Response({"results": chart_data}, status=status.HTTP_200_OK)
 

    @extend_schema(parameters=[
        OpenApiParameter('category', type=str, description='Filter by category (alert, polls)'),
        OpenApiParameter('interval', type=str, description='Time interval (hour, week, month)', required=True),
    ])
    @action(detail=False, methods=["get"])
    def delivery_rate(self, request):
        user = self.request.user
        category = request.query_params.get('category', None)

        if user.role == 'superadmin':
            queryset = RecallMessage.objects.filter(created_by=request.user)
        elif request.user.role == "member":
            return Response(
                {"detail": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN,
            )
        else:
            queryset = RecallMessage.objects.filter(
                created_by=request.user.invited_by)

        interval = request.query_params.get('interval', None)

        if interval is None:
            return Response({"detail": "interval is required"})

        end_time = timezone.now()

        if interval == 'hour':
            start_time = end_time - timedelta(hours=1)
        elif interval == 'week':
            start_time = end_time - timedelta(weeks=1)
        elif interval == 'month':
            start_time = end_time - timedelta(days=30)
        else:
            return Response({"detail": "Invalid time interval"}, status=status.HTTP_400_BAD_REQUEST)

        if category is not None:
            recall_messages = queryset.filter(created_on__range=(
                start_time, end_time), category=category)
        else:
            recall_messages = queryset.filter(
                created_on__range=(start_time, end_time))

        members_count = recall_messages.aggregate(
            members_count=Count('members'))['members_count']
        members_count = members_count if members_count is not None else 0

        acknowledged = recall_messages.filter(
            acknowledged__isnull=False).count()

        opened = (acknowledged / members_count) * \
            100 if members_count > 0 else 0
        # opened = persentage of the acknowleged and membercount
        chart_data = [
            {
                "category": "Successful",
                "value": 100,
            },
            {
                "category": "Delivered",
                "value": 100,
            },
            {
                "category": "Failed",
                "value": 0,
            },
            {
                "category": "Opened",
                "value": round(opened, 2),
            },
        ]

        return Response({"results": chart_data}, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=["get"])
    def leaderboard(self, request):
        user = self.request.user
        if user.role == 'superadmin':
            queryset = Member.objects.filter(created_by=request.user)
        elif request.user.role == "member":
            return Response(
                {"detail": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN,
            )
        else:
            queryset = Member.objects.filter(
                created_by=request.user.invited_by)

        chart_data = [
            {
                'name': member.first_name,
                'file': member.user.profile_pic.url if member.user and member.user.profile_pic else None,
                'track': index + 1,
                'value': (index + 1) * 100

            } for index, member in enumerate(queryset)]

        return Response({"results": chart_data}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"])
    def active_users(self, request):
        user = self.request.user
        if user.role == 'superadmin':
            queryset = Member.objects.filter(created_by=request.user)
        elif request.user.role == "member":
            return Response(
                {"detail": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN,
            )
        else:
            queryset = Member.objects.filter(
                created_by=request.user.invited_by)

        chart_data = [
            {
                'name': member.first_name,
                'steps': (index + 1) * 100,
                'file': member.user.profile_pic.url if member.user and member.user.profile_pic else None,

            } for index, member in enumerate(queryset)]

        return Response({"results": chart_data}, status=status.HTTP_200_OK)


    @extend_schema(parameters=[
        OpenApiParameter('interval', type=str, description='Time interval (month, week)', required=True),
        OpenApiParameter('category', type=str, description='Filter by category (alert, polls)'),
    ])
    @action(detail=False, methods=["get"])
    def incident_timeline(self, request):
        user = self.request.user
        interval = request.query_params.get('interval', None)
        category = request.query_params.get('category', None)

        if interval is None:
            return Response({"detail": "interval is required"})
        if user.role == 'superadmin':
            queryset = RecallMessage.objects.filter(created_by=request.user)
        elif request.user.role == "member":
            return Response(
                {"detail": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN,
            )
        else:
            queryset = RecallMessage.objects.filter(
                created_by=request.user.invited_by)

        end_time = timezone.now()
        chart_data = []
        if interval == 'month':
            month_data = {
                '1D': end_time - timedelta(days=1),
                '5D': end_time - timedelta(days=5),
                '10D': end_time - timedelta(days=10),
                '15D': end_time - timedelta(days=15),
                '20D': end_time - timedelta(days=20),
                '25D': end_time - timedelta(days=25),
                '30D': end_time - timedelta(days=30),
            }

            if category is not None:
                chart_data += [
                    {
                        'country': start_time,
                        'value': queryset.filter(created_on__range=(month_data[start_time], end_time), category=category).count(),
                    } for start_time in month_data
                ]
            else:
                chart_data += [
                    {
                        'country': start_time,
                        'value': queryset.filter(created_on__range=(month_data[start_time], end_time)).count(),
                    } for start_time in month_data
                ]

        elif interval == 'week':

            if category is not None:
                chart_data += [
                    {
                        'country': (end_time + timedelta(days=i)).strftime('%a'),
                        'value': queryset.filter(created_on__date=(end_time - timedelta(days=i)), category=category).count(),
                    } for i in range(7)
                ]
            else:
                chart_data += [
                    {
                        'country': (end_time + timedelta(days=i)).strftime('%a'),
                        'value': queryset.filter(created_on__date=(end_time - timedelta(days=i))).count(),
                    } for i in range(7)
                ]

        return Response({"results": chart_data}, status=status.HTTP_200_OK)
    

    @extend_schema(parameters=[
        OpenApiParameter('interval', type=str, description='Time interval (month, week)', required=True),
        OpenApiParameter('category', type=str, description='Filter by category (alert, polls)'),
    ])
    @action(detail=False, methods=["get"])
    def incident_timeline_linechart(self, request):
        user = self.request.user
        interval = request.query_params.get('interval', None)
        category = request.query_params.get('category', None)

        if interval is None:
            return Response({"detail": "interval is required"})
        if user.role == 'superadmin':
            queryset = RecallMessage.objects.filter(created_by=request.user)
        elif request.user.role == "member":
            return Response(
                {"detail": "You do not have permission to perform this action."},
                status=status.HTTP_403_FORBIDDEN,
            )
        else:
            queryset = RecallMessage.objects.filter(
                created_by=request.user.invited_by)
        end_time = timezone.now()
        chart_data = []

        if interval not in ['month', 'week']:
            return Response({"detail": "Invalid interval provided"}, status=status.HTTP_400_BAD_REQUEST)

        days = 30 if interval == 'month' else 6

        for day in range(days, -1, -1):  # 6 days ago to 0 days ago (past week)

            current_date = end_time - timedelta(days=day)
            previous_date = current_date - timedelta(days=1)
            if category is not None:
                data = queryset.filter(
                    created_on__date=current_date, category=category)
            else:
                data = queryset.filter(created_on__date=current_date)

            chart_data.append({
                "date": current_date,
                "value": data.count(),
                "previousDate": previous_date
            })

        return Response({"results": chart_data}, status=status.HTTP_200_OK)

class QuickPreference_Viewset(BaseViewSet):
    serializer_class = QuickPreferenceSerializer
    queryset = QuickPreference.objects.all()
    http_method_names = ['get']

    @extend_schema(description="QuickPreference List API")
    def list(self, request, *args, **kwargs):
        try:
            self.queryset = self.filter_queryset(self.get_queryset())
            serializer = self.get_serializer(self.queryset, many=True)
            return Response({"results":serializer.data})
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)
    
class Preference_Viewset(BaseViewSet):

    serializer_class = GenericPreferenceSerializer
    queryset = GenericPreference.objects.select_related("quick_preference","hot_buttons")
    @extend_schema(parameters=[OpenApiParameter('zip', type=int, description='Filter by ZIP code')])
    
    
    def get_serializer_class(self):
        if self.action == "change_preferences":
            return ChangePreferenceSerializer
        else:
            return GenericPreferenceSerializer
    
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
    
    def get_permissions(self):
        permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]
    
    def get_queryset(self):
        user = self.request.user
        # Type Of Preferences Are = quick_preference ,user_preference ,hot_buttons
        preference_type = self.request.query_params.get('type', "quick_preference")
        return self.queryset.filter(user__in=[user],type=preference_type,is_default=False).order_by("-display_order")
    

    def list(self, request, *args, **kwargs):
        try:
            self.queryset = self.get_queryset()
            serializer = self.get_serializer(self.queryset, many=True)
            preference_type = self.request.query_params.get('type', "quick_preference")
            data=serializer.data
            preference=[]
        
            if(data==[]):
                if(preference_type=="quick_preference"):
                    preference= QuickPreferenceSerializer(QuickPreference.objects.all().order_by("-display_order"),many=True).data
                    
                elif(preference_type=="user_preference"):
                    preference=GenericUserPreferencesSerializer(GenericUserPreferences.objects.all(),many=True).data   
                    
                elif(preference_type=="hot_buttons"):
                    hotbuttons = HotButton.objects.filter(created_by=self.request.user.invited_by, is_available_for_members=True).order_by("-display_order")             
                    preference = HotButtonSerializer(hotbuttons, many=True).data
                else:   
                    preference = GenericPreferenceSerializer(GenericPreference.objects.filter(is_default=True,type=preference_type).order_by("display_order"),many=True).data
                preference=[{k: v for k, v in item.items() if k != 'id'} for item in preference]
            else:   
                preference = GenericPreferenceSerializer(self.queryset,many=True).data
            
                
            if(preference==[]):
                return Response({"details":"No user preference found!"},status=status.HTTP_404_NOT_FOUND)
                
            return Response({"details":preference},status=status.HTTP_200_OK)

        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)
        
    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
           
            serializer.is_valid(raise_exception=True)
           
            self.perform_create(serializer)
           
            headers = self.get_success_headers(serializer.data)
           
            return Response(
                serializer.data, status=status.HTTP_201_CREATED, headers=headers
            )
            
        except ValidationError as e:
            field_name, error_message = serailizer_errors(e)
           
            detail = f"{field_name} - {error_message}"
           
            if (field_name == "non_field_errors"):
                detail = f"{error_message}"
                return Response(
                    {"detail": detail},
                    status=status.HTTP_400_BAD_REQUEST,
                )
           
            return Response(
                {"detail": detail},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as ex:
            logger.info("Something went wrong", exc_info=ex)
            raise APIException(detail=ex)
    
    @action(detail=False, methods=["post"])
    def change_preferences(self, request, *args, **kwargs):
        try:
            
            prefrences = self.request.data.get('preferences')
            
            for prefrence in prefrences:
                #Find if prefrence exists
                if(prefrence.get('id',None)):
                    instance = get_object_or_404(GenericPreference, pk=prefrence.get('id'))
                    serializer = GenericPreferenceSerializer(instance,data=prefrence)
                    if serializer.is_valid():
                        serializer.save()
                        return Response(serializer.data, status=status.HTTP_200_OK)
                    
                else:
                    serializer = GenericPreferenceSerializer(data=prefrence)
                    if serializer.is_valid(raise_exception=True):
                        serializer.save(user=self.request.user)
                    
            return Response(
                {"detail": "Preferences changes succesfully!"}
            )
            
        except ValidationError as e:
            field_name, error_message = serailizer_errors(e)
            return Response(
                {"detail": f"{field_name} - {error_message}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except APIException as api_exception:
            # Handle APIException specifically
            logger.error("APIException occurred", exc_info=api_exception)
            return Response(
                {"detail": str(api_exception)}, status=api_exception.status_code
            )

        except Exception as ex:
            logger.error("Unexpected exception occurred", exc_info=ex)
            raise APIException(detail=ex)

class ActionImpactResultOptionsAPIView(BaseAPIView):
    
    def get(self, request):
        try:
            result_type = request.GET.get("type", "impact")
            category = request.GET.get("category")
            sub_category = request.GET.get("sub_category")
  

            data = ActionImpactResultOptions.objects.all().order_by('category')
            
            if category:
                data = data.filter(category__in=category.split(","))
            if sub_category:
                data = data.filter(sub_category__in=sub_category.split(","))

            
            results = data.values('category', 'sub_category', result_type)
            
            grouped_data = {}

            for result in results:
                categories = result['category']
                sub_categories = result['sub_category']
                result_value = result[result_type]
                
                if sub_categories:
                    if categories not in grouped_data:
                        grouped_data[categories] = {}
                    if sub_categories not in grouped_data[categories]:
                        grouped_data[categories][sub_categories] = []
                    grouped_data[categories][sub_categories].append(result_value)
                else:
                    if categories not in grouped_data:
                        grouped_data[categories] = []
                    grouped_data[categories].append(result_value)
                
            
            #Returning General First Then Other Categories
            # if(sub_category or category):
            return Response({'results': grouped_data})
            # else:
                # general = grouped_data.pop("General")
                # new_data= {"General": general } 
                # new_data.update(grouped_data)
                # return Response({'results': grouped_data})
            
        except Exception as ex:
            logger.error("Something went wrong", exc_info=ex)
            raise APIException(detail=str(ex))


class PublishNarrativesAPIView(BaseAPIView):
    queryset = EPBOPB.objects.all()
    serializer_class = EPBOPBSerializer
    page_size_query_param = "page_size"
    
    def get_queryset(self):
        category = self.request.query_params.get('category', None)
        type = self.request.query_params.get('type', None)
        start_date = self.request.query_params.get('start_date', None)
        end_date = self.request.query_params.get('end_date', None)
        q = self.request.query_params.get("q")
        favorite = self.request.query_params.get("favorite")
        
        if q:
            self.queryset  = self.queryset.filter(
                Q(title__icontains=q)
                | Q(category__icontains=q)
                | Q(adverb__icontains=q)
                | Q(bullet__icontains=q)
            )

        if category:
            self.queryset = self.queryset.filter(category=category)
            
        if favorite:
            if(favorite == 'true'): self.queryset = self.queryset.filter(favorite= True)
            else:self.queryset = self.queryset.filter(favorite= False)        
        if type:
            self.queryset = self.queryset.filter(type=type)
            
        if (start_date and end_date):
            self.queryset = self.queryset.filter(created_on__range=(start_date, end_date))
        
        return self.queryset.filter(is_public=True).order_by("-created_on")
    
    
    def get(self, request):
        try:
            page = self.paginate_queryset(self.get_queryset(),request=request)
            if page is not None:
                serializer = self.serializer_class(page, many=True)
                return self.get_paginated_response(serializer.data)
            
            serializer = self.serializer_class(self.queryset, many=True)
            return Response(serializer.data)

        except Exception as ex:
            logger.error("Something went wrong", exc_info=ex)
            raise APIException(detail=str(ex))
                
        
@csrf_exempt
def send_fcm(request):
    from total_recall import settings
    from pyfcm import FCMNotification
    push_service = FCMNotification(api_key= settings.FCM_API_KEY)
    topic = 'weekly_reminder'
    message_title = "Weekly Reminder"
    message_body = "Have you logged into the application?"
    data_message = {
        "title": message_title,
        "body": message_body,
        "priority": "high"
    }
    response = push_service.notify_topic_subscribers(topic_name=topic, message_body=data_message)
    
    return JsonResponse(response)

class ActionImpactResultHistoryViewset(BaseViewSet):
    serializer_class = ActionImpactResultOptionsHistorySerializer
    queryset = ActionImpactResultOptionsHistory.objects.select_related("created_by")
    
    def get_queryset(self):
        type = self.request.query_params.get('type',"action")
        return self.queryset.filter(created_by=self.request.user,type = type)
    
    def create(self, request, *args, **kwargs):
        try:
            data = request.data
            type = request.query_params.get('type',"action")
            category = request.query_params.get('category',"true")
            value = request.data.get('value')
            if(not value):
                return Response(
                    {"detail": "Value not found ! "},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            histories = ActionImpactResultOptionsHistory.objects.filter(type=type,created_by=request.user).order_by("updated_on")
            if(len(histories)<2):
                if(category=="true"):
                    ActionImpactResultOptionsHistory.objects.create(type=type,created_by=request.user,history=value)
                else:
                    ActionImpactResultOptionsHistory.objects.create(type=type,created_by=request.user,subcategory_history=value)
            else:
                if(category=="true"):
                    histories.first().subcategory_history=value
                else:
                    histories.first().history=value
                histories.first().save()
                
            return Response(
                {"detail": "Successfully Created!"},
                status=status.HTTP_201_CREATED,
            )
        except ValidationError as e:
            field_name, error_message = serailizer_errors(e)
            return Response(
                {"detail": f"{field_name} - {error_message}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except ActionImpactResultOptions.DoesNotExist:
            return Response(
                {"detail": f"History not found!"},
                status=status.HTTP_404_NOT_FOUND,
            )
        
        except Exception as ex:
            logger.error("Something went wrong", exc_info=ex)
            raise APIException(detail=str(ex))

class VerbAPIView(BaseAPIView):
    serializer_class = VerbSerializer
    queryset = Verb.objects.all()
    pagination_class = CustomPagination

    def get(self, request):
        verbs = self.queryset.all()
        paginator = self.pagination_class() 
        paginated_verbs = paginator.paginate_queryset(verbs, request) 
        data = self.serializer_class(paginated_verbs, many=True).data
        return paginator.get_paginated_response(data)
        
        
        



# ==============================================================================================================



# from django.views import View
# from django.shortcuts import render, redirect
# from django.http import HttpResponse, JsonResponse
# from django.contrib.auth import authenticate, login, logout
# from django.contrib.auth.models import User
# from django.core.exceptions import ObjectDoesNotExist
# from ..models import Products, Category, Cart
# import json
# import razorpay
# from django.conf import settings

# class HomeView(View):
#     def get(self, request):
#         try:
#             products = Products.objects.all()  # Retrieve all products from the database
#             return render(request, 'ecomapp/home.html', {'products': products})
#         except Exception as e:
#             return HttpResponse("An error occurred: {}".format(str(e)))

# class SignupView(View):
#     def get(self, request):
#         return render(request, 'ecomapp/components/signup.html')
    
#     def post(self, request):
#         try:
#             user_data = {field: request.POST.get(field) for field in ['name', 'email', 'password', 'gender', 'adress', 'phone']}
#             existing_user = User.objects.filter(email=user_data['email']).exists()
#             if existing_user:
#                 return render(request, 'ecomapp/home.html', {'message': "User already exists"})
#             else:
#                 user = User.objects.create_user(first_name=user_data['name'], username=user_data['email'], email=user_data['email'], password=user_data['password'])
#                 return render(request, 'ecomapp/home.html')
#         except Exception as e:
#             return HttpResponse("An error occurred: {}".format(str(e)))

# class HandleLoginView(View):
#     def get(self, request):
#         return render(request, 'ecomapp/components/login.html')
    
#     def post(self, request):
#         try:
#             username = request.POST.get('email')
#             userpassword = request.POST.get('password')
#             user = User.objects.filter(username=username).first()
#             if user is None:
#                 return render(request, "ecomapp/home.html", {"message": "User is not registered"})
#             myuser = authenticate(username=username, password=userpassword)
#             if myuser is not None:
#                 login(request, myuser)
#                 return render(request, "ecomapp/home.html", {"user": user})
#             else:
#                 return render(request, "ecomapp/home.html")
#         except Exception as e:
#             return HttpResponse("An error occurred: {}".format(str(e)))

# class HandleLogoutView(View):
#     def get(self, request):
#         logout(request)
#         return redirect('/Authapp/login')

# class ProductView(View):
#     def get(self, request):
#         try:
#             products = Products.objects.select_related("category").all()
#             return render(request, 'ecomapp/products.html', {'products': products})
#         except Exception as e:
#             return HttpResponse("An error occurred: {}".format(str(e)))
        
#     def post(self, request):
#         try:
#             product_for_search = request.POST.get('name')
#             search_product = Products.objects.filter(product_name__icontains=product_for_search)
#             return render(request, 'ecomapp/products.html', {'products': search_product})
#         except Exception as e:
#             return HttpResponse("An error occurred: {}".format(str(e)))

# class ProfileView(View):
#     def get(self, request):
#         if request.user.is_authenticated:
#             user_details = User.objects.filter(email=request.user.email).first()
#             return render(request, "ecomapp/components/profile.html", {"user": user_details})
#         else:
#             return HttpResponse("You are not authenticated")

# class CartView(View):
#     def post(self, request):
#         try:
#             if request.user.is_authenticated:
#                 product_id = request.POST.get('product_id')
#                 user_id = request.user.email
#                 cart_object, _ = Cart.objects.get_or_create(user_id=user_id, Product_id=product_id)
#                 cart_object.quantity += 1
#                 cart_object.save()
#                 return redirect("cart")
#             else:
#                 return render(request, "ecomapp/components/login.html", {"message": "You are not authenticated"})
#         except Exception as e:
#             return HttpResponse("An error occurred: {}".format(str(e)))

#     def get(self, request):
#         try:
#             if request.user.is_authenticated:
#                 user_mail = request.user.email
#                 cart_items = Cart.objects.filter(user_id=user_mail).select_related("product")
#                 total_price = sum(cart_item.product.price for cart_item in cart_items)
#                 return render(request, "ecomapp/components/cart.html", {"products": cart_items, "total_price": total_price})
#             else:
#                 return render(request, "ecomapp/components/login.html", {"message": "You are not authenticated"})
#         except Exception as e:
#             return HttpResponse("An error occurred: {}".format(str(e)))

# class CartDeleteView(View):
#     def post(self, request):
#         try:
#             product_id = request.POST.get('product_id')
#             Cart.objects.filter(Product_id=product_id).delete()
#             return redirect('/Authapp/cart')
#         except Exception as e:
#             return HttpResponse("An error occurred: {}".format(str(e)))

# class CreateOrderView(View):
#     def post(self, request):
#         try:
#             data = json.loads(request.body)
#             payment_amount = data["amount"]
#             client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#             order = client.order.create({
#                 "amount": payment_amount,
#                 "currency": "INR",
#                 "payment_capture": "1"
#             })
#             return JsonResponse({
#                 "order_id": order["id"],
#                 "razorpay_key": settings.RAZORPAY_KEY_ID,
#                 "amount": payment_amount,
#             })
#         except Exception as e:
#             return HttpResponse("An error occurred: {}".format(str(e)))
