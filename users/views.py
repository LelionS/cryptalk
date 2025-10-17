from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from .models import EmailOTP, User
from .serializers import RegisterSerializer
from .utils import generate_otp, send_otp_via_email


# ===============================================================
# ======================  REST API VIEWS  ========================
# ===============================================================

class RegisterView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=400)

        if User.objects.filter(email=email).exists():
            return Response({'error': 'User already exists'}, status=400)

        otp = generate_otp()
        send_otp_via_email(email, otp)
        EmailOTP.objects.create(email=email, otp=otp)

        return Response({'message': 'OTP sent to email'}, status=200)


class VerifyEmailView(APIView):
    def post(self, request):
        email = request.data.get('email')
        code = request.data.get('code')
        password = request.data.get('password')

        if not all([email, code, password]):
            return Response({'error': 'Email, code, and password are required'}, status=400)

        try:
            otp_entry = EmailOTP.objects.filter(email=email).latest('created_at')
        except EmailOTP.DoesNotExist:
            return Response({'error': 'No OTP found'}, status=400)

        if otp_entry.otp != code or not otp_entry.is_valid():
            return Response({'error': 'Invalid or expired OTP'}, status=400)

        serializer = RegisterSerializer(data={'email': email, 'password': password})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({'message': 'Account created successfully'}, status=201)


class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'Invalid credentials'}, status=400)

        if not user.check_password(password):
            return Response({'error': 'Invalid credentials'}, status=400)

        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=200)


# ===============================================================
# ====================  WEB INTERFACE VIEWS  =====================
# ===============================================================

def register_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        if not email or not password:
            messages.error(request, "Email and password are required.")
            return redirect("register")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return redirect("register")

        otp = generate_otp()
        send_otp_via_email(email, otp)
        EmailOTP.objects.create(email=email, otp=otp)

        request.session["pending_email"] = email
        request.session["pending_password"] = password

        messages.success(request, f"OTP sent to {email}. Enter it to verify.")
        return redirect("verify_email")

    return render(request, "register.html")



def verify_email_view(request):
    email = request.session.get("pending_email")
    password = request.session.get("pending_password")

    if not email or not password:
        messages.error(request, "No registration in progress.")
        return redirect("register")

    if request.method == "POST":
        code = request.POST.get("otp")

        try:
            otp_entry = EmailOTP.objects.filter(email=email).latest("created_at")
        except EmailOTP.DoesNotExist:
            messages.error(request, "No OTP found.")
            return redirect("verify_email")

        if not otp_entry.is_valid() or otp_entry.otp != code:
            messages.error(request, "Invalid or expired OTP.")
            return redirect("verify_email")

        # Create user placeholder (without username yet)
        user = User.objects.create_user(
            email=email,
            username=f"user_{User.objects.count()+1}",  # temporary unique username
            password=password
        )

        request.session["verified_user_id"] = user.id
        del request.session["pending_email"]
        del request.session["pending_password"]

        messages.success(request, "Email verified. Now set up your username.")
        return redirect("set_username")

    return render(request, "verify_email.html", {"email": email})


def set_username_view(request):
    user_id = request.session.get("verified_user_id")

    if not user_id:
        messages.error(request, "No verified user found.")
        return redirect("register")

    user = User.objects.get(id=user_id)

    if request.method == "POST":
        username = request.POST.get("username").strip()

        if not username:
            messages.error(request, "Username cannot be empty.")
            return redirect("set_username")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return redirect("set_username")

        user.username = username
        user.save()
        del request.session["verified_user_id"]

        messages.success(request, "Username set successfully. You can now log in.")
        return redirect("login")

    return render(request, "set_username.html")

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            return redirect("home")
        else:
            messages.error(request, "Invalid credentials.")

    return render(request, "login.html")


def home_view(request):
    return render(request, "home.html", {"user": request.user})
