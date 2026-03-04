<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        ${msg("TelegramCodeTitle")!"Подтверждение входа"}
    <#elseif section = "form">
        <form id="kc-telegram-otp-form" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="otp" class="${properties.kcLabelClass!}">
                        ${msg("TelegramCodeText")!"Код из Telegram"}
                    </label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="otp" name="otp" class="${properties.kcInputClass!}" autofocus autocomplete="off" />
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                           type="submit" value=${msg("TelegramEnterText")!"Войти"}>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>