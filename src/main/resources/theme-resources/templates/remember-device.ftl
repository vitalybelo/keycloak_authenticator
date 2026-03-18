<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false displayMessage=false; section>
    <#if section = "header">
        ${msg("rememberDeviceTitle")}
    <#elseif section = "form">
        <form id="kc-remember-device-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">

            <#-- Имитация стандартного информационного сообщения Keycloak -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="alert alert-success" style="margin-top: 10px; margin-bottom: 20px;">
                    <span class="pficon pficon-ok"></span>
                    <span class="kc-feedback-text">${msg("rememberDeviceAuthSuccess")}</span>
                </div>
            </div>

            <#-- Стандартный чекбокс в стиле темы -->
            <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}">
                        <div class="checkbox">
                            <label>
                                <input type="checkbox" name="rememberDevice" id="rememberDevice" <#--checked-->>
                                ${msg("rememberDeviceLabel")}
                            </label>
                        </div>
                    </div>
                </div>
            </div>

            <#-- НОВОЕ ПОЛЕ: Ввод кастомного названия устройства -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="deviceNameInput" class="${properties.kcLabelClass!}">${msg("deviceNameLabel", "Название устройства (необязательно)")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="deviceNameInput" name="deviceNameInput" class="${properties.kcInputClass!}" placeholder="${msg("deviceNamePlaceholder", "Например: Мой рабочий ноутбук")}"/>
                </div>
            </div>

            <#-- Стандартная кнопка -->
            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                           type="submit" value="${msg("rememberDeviceContinue")}"/>
                </div>
            </div>

        </form>
    </#if>
</@layout.registrationLayout>