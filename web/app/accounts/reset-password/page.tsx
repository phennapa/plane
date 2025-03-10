"use client";

import { useEffect, useMemo, useState } from "react";
import { observer } from "mobx-react";
import Image from "next/image";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
// icons
import { useTheme } from "next-themes";
import { Eye, EyeOff } from "lucide-react";
// ui
import { useTranslation } from "@plane/i18n";
import { Button, Input } from "@plane/ui";
// components
import { AuthBanner, PasswordStrengthMeter } from "@/components/account";
// helpers
import {
  EAuthenticationErrorCodes,
  EErrorAlertType,
  EPageTypes,
  TAuthErrorInfo,
  authErrorHandler,
} from "@/helpers/authentication.helper";
import { API_BASE_URL } from "@/helpers/common.helper";
import { E_PASSWORD_STRENGTH, getPasswordStrength } from "@/helpers/password.helper";
// wrappers
import { AuthenticationWrapper } from "@/lib/wrappers";
// services
// images
import PlaneBackgroundPatternDark from "@/public/auth/background-pattern-dark.svg";
import PlaneBackgroundPattern from "@/public/auth/background-pattern.svg";
import BlackHorizontalLogo from "@/public/plane-logos/black-horizontal-with-blue-logo.png";
import WhiteHorizontalLogo from "@/public/plane-logos/white-horizontal-with-blue-logo.png";
import { AuthService } from "@/services/auth.service";

type TResetPasswordFormValues = {
  email: string;
  password: string;
  confirm_password?: string;
};

const defaultValues: TResetPasswordFormValues = {
  email: "",
  password: "",
};

// services
const authService = new AuthService();

const ResetPasswordPage = observer(() => {
  // search params
  const searchParams = useSearchParams();
  const uidb64 = searchParams.get("uidb64");
  const token = searchParams.get("token");
  const email = searchParams.get("email");
  const error_code = searchParams.get("error_code");
  // states
  const [showPassword, setShowPassword] = useState({
    password: false,
    retypePassword: false,
  });
  const [resetFormData, setResetFormData] = useState<TResetPasswordFormValues>({
    ...defaultValues,
    email: email ? email.toString() : "",
  });
  const [csrfToken, setCsrfToken] = useState<string | undefined>(undefined);
  const [isPasswordInputFocused, setIsPasswordInputFocused] = useState(false);
  const [isRetryPasswordInputFocused, setIsRetryPasswordInputFocused] = useState(false);
  const [errorInfo, setErrorInfo] = useState<TAuthErrorInfo | undefined>(undefined);
  // plane hooks
  const { t } = useTranslation();
  // hooks
  const { resolvedTheme } = useTheme();

  const handleShowPassword = (key: keyof typeof showPassword) =>
    setShowPassword((prev) => ({ ...prev, [key]: !prev[key] }));

  const handleFormChange = (key: keyof TResetPasswordFormValues, value: string) =>
    setResetFormData((prev) => ({ ...prev, [key]: value }));

  useEffect(() => {
    if (csrfToken === undefined)
      authService.requestCSRFToken().then((data) => data?.csrf_token && setCsrfToken(data.csrf_token));
  }, [csrfToken]);

  const isButtonDisabled = useMemo(
    () =>
      !!resetFormData.password &&
      getPasswordStrength(resetFormData.password) === E_PASSWORD_STRENGTH.STRENGTH_VALID &&
      resetFormData.password === resetFormData.confirm_password
        ? false
        : true,
    [resetFormData]
  );

  useEffect(() => {
    if (error_code) {
      const errorhandler = authErrorHandler(error_code?.toString() as EAuthenticationErrorCodes);
      if (errorhandler) {
        setErrorInfo(errorhandler);
      }
    }
  }, [error_code]);

  const password = resetFormData?.password ?? "";
  const confirmPassword = resetFormData?.confirm_password ?? "";
  const renderPasswordMatchError = !isRetryPasswordInputFocused || confirmPassword.length >= password.length;

  const logo = resolvedTheme === "light" ? BlackHorizontalLogo : WhiteHorizontalLogo;

  return (
    <AuthenticationWrapper pageType={EPageTypes.NON_AUTHENTICATED}>
      <div className="relative w-screen h-screen overflow-hidden">
        <div className="absolute inset-0 z-0">
          <Image
            src={resolvedTheme === "dark" ? PlaneBackgroundPatternDark : PlaneBackgroundPattern}
            className="w-full h-full object-cover"
            alt="Plane background pattern"
          />
        </div>
        <div className="relative z-10 w-screen h-screen overflow-hidden overflow-y-auto flex flex-col">
          <div className="container min-w-full px-10 lg:px-20 xl:px-36 flex-shrink-0 relative flex items-center justify-between pb-4 transition-all">
            <div className="flex items-center gap-x-2 py-10">
              <Link href={`/`} className="h-[30px] w-[133px]">
                <Image src={logo} alt="Plane logo" />
              </Link>
            </div>
          </div>
          <div className="flex-grow container mx-auto max-w-lg px-10 lg:max-w-md lg:px-5 py-10 lg:pt-28 transition-all">
            <div className="relative flex flex-col space-y-6">
              <div className="text-center space-y-1 py-4">
                <h3 className="flex gap-4 justify-center text-3xl font-bold text-onboarding-text-100">
                  {t("auth.reset_password.title")}
                </h3>
                <p className="font-medium text-onboarding-text-400">{t("auth.reset_password.description")}</p>
              </div>
              {errorInfo && errorInfo?.type === EErrorAlertType.BANNER_ALERT && (
                <AuthBanner bannerData={errorInfo} handleBannerData={(value) => setErrorInfo(value)} />
              )}
              <form
                className="mt-5 space-y-4"
                method="POST"
                action={`${API_BASE_URL}/auth/reset-password/${uidb64?.toString()}/${token?.toString()}/`}
              >
                <input type="hidden" name="csrfmiddlewaretoken" value={csrfToken} />
                <div className="space-y-1">
                  <label className="text-sm text-onboarding-text-300 font-medium" htmlFor="email">
                    {t("auth.common.email.label")}
                  </label>
                  <div className="relative flex items-center rounded-md bg-onboarding-background-200">
                    <Input
                      id="email"
                      name="email"
                      type="email"
                      value={resetFormData.email}
                      //hasError={Boolean(errors.email)}
                      placeholder={t("auth.common.email.placeholder")}
                      className="h-[46px] w-full border border-onboarding-border-100 !bg-onboarding-background-200 pr-12 text-onboarding-text-400 cursor-not-allowed"
                      autoComplete="on"
                      disabled
                    />
                  </div>
                </div>
                <div className="space-y-1">
                  <label className="text-sm text-onboarding-text-300 font-medium" htmlFor="password">
                    {t("auth.common.password.label")}
                  </label>
                  <div className="relative flex items-center rounded-md bg-onboarding-background-200">
                    <Input
                      type={showPassword.password ? "text" : "password"}
                      name="password"
                      value={resetFormData.password}
                      onChange={(e) => handleFormChange("password", e.target.value)}
                      //hasError={Boolean(errors.password)}
                      placeholder={t("auth.common.password.placeholder")}
                      className="h-[46px] w-full border border-onboarding-border-100 !bg-onboarding-background-200 pr-12 placeholder:text-onboarding-text-400"
                      minLength={8}
                      onFocus={() => setIsPasswordInputFocused(true)}
                      onBlur={() => setIsPasswordInputFocused(false)}
                      autoComplete="on"
                      autoFocus
                    />
                    {showPassword.password ? (
                      <EyeOff
                        className="absolute right-3 h-5 w-5 stroke-custom-text-400 hover:cursor-pointer"
                        onClick={() => handleShowPassword("password")}
                      />
                    ) : (
                      <Eye
                        className="absolute right-3 h-5 w-5 stroke-custom-text-400 hover:cursor-pointer"
                        onClick={() => handleShowPassword("password")}
                      />
                    )}
                  </div>
                  <PasswordStrengthMeter password={resetFormData.password} isFocused={isPasswordInputFocused} />
                </div>
                <div className="space-y-1">
                  <label className="text-sm text-onboarding-text-300 font-medium" htmlFor="confirm_password">
                    {t("auth.common.password.confirm_password.label")}
                  </label>
                  <div className="relative flex items-center rounded-md bg-onboarding-background-200">
                    <Input
                      type={showPassword.retypePassword ? "text" : "password"}
                      name="confirm_password"
                      value={resetFormData.confirm_password}
                      onChange={(e) => handleFormChange("confirm_password", e.target.value)}
                      placeholder={t("auth.common.password.confirm_password.placeholder")}
                      className="h-[46px] w-full border border-onboarding-border-100 !bg-onboarding-background-200 pr-12 placeholder:text-onboarding-text-400"
                      onFocus={() => setIsRetryPasswordInputFocused(true)}
                      onBlur={() => setIsRetryPasswordInputFocused(false)}
                    />
                    {showPassword.retypePassword ? (
                      <EyeOff
                        className="absolute right-3 h-5 w-5 stroke-custom-text-400 hover:cursor-pointer"
                        onClick={() => handleShowPassword("retypePassword")}
                      />
                    ) : (
                      <Eye
                        className="absolute right-3 h-5 w-5 stroke-custom-text-400 hover:cursor-pointer"
                        onClick={() => handleShowPassword("retypePassword")}
                      />
                    )}
                  </div>
                  {!!resetFormData.confirm_password &&
                    resetFormData.password !== resetFormData.confirm_password &&
                    renderPasswordMatchError && (
                      <span className="text-sm text-red-500">{t("auth.common.password.errors.match")}</span>
                    )}
                </div>
                <Button type="submit" variant="primary" className="w-full" size="lg" disabled={isButtonDisabled}>
                  {t("auth.common.password.submit")}
                </Button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </AuthenticationWrapper>
  );
});

export default ResetPasswordPage;
