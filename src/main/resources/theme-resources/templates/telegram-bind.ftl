<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>

    <#if section = "header">
        ${msg("TelegramBindTitle")!"Привязка Telegram (2FA)"}
    <#elseif section = "form">

        <div id="kc-telegram-bind-container" style="text-align: center;">
            <p style="margin-bottom: 20px; color: #666;">
                ${msg("TelegramBindText")!"Для обеспечения безопасности аккаунта необходимо привязать ваш Telegram"}
            </p>

            <#-- лучше передавать из Java-провайдера через context.form().setAttribute -->
            <#assign botName = "vitaly_belo_bot">
            <#assign tgLink = "https://t.me/" + botName + "?start=" + tgToken>

            <#-- QR-код -->
            <div style="margin: 20px auto; padding: 10px; background: white; display: inline-block; border-radius: 8px;">
                <#-- ВНИМАНИЕ: Для production лучше использовать локальную JS-библиотеку (например qrcode.js)
                     или генерировать Base64 картинку в Java, чтобы не нарушать Content Security Policy (CSP) Keycloak.
                     Здесь для простоты примера используется внешний API. -->
                <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${tgLink?url('UTF-8')}" alt="Telegram QR Code" />
            </div>

            <#-- Кнопка для мобильных устройств (открывает приложение Telegram) -->
            <div style="margin-bottom: 20px;">
                <a href="${tgLink}" target="_blank" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}">
                    ${msg("TelegramButtonText")!"Открыть Telegram"}
                </a>
            </div>

            <p style="font-size: 14px;">
                ${msg("TelegramHelpText")?no_esc!"Отсканируйте QR-код или нажмите кнопку выше,<br>а затем нажмите <b>\"Запустить\" (Start)</b> в боте"}
            </p>

            <#-- Индикатор загрузки (спрятан по умолчанию) -->
            <div id="tg-success-message" style="display: none; margin-top: 20px; color: #28a745; font-weight: bold;">
                ${msg("TelegramSuccessText")!"✓ Telegram успешно привязан! Перенаправляем..."}
            </div>
        </div>

        <#-- Скрипт фонового опроса (AJAX Polling) -->
        <script>
            document.addEventListener("DOMContentLoaded", function() {
                const actionUrl = "${url.loginAction}";
                // Новый URL для поллинга (realm.name доступен в контексте FTL)
                const pollUrl = "/realms/${realm.name}/telegram/status/${tgToken}";

                const pollInterval = setInterval(() => {
                    fetch(pollUrl, {
                        method: 'GET',
                        headers: { 'Accept': 'application/json' }
                    })
                        .then(response => response.json())
                        .then(data => {
                            if (data.status === "linked") {
                                clearInterval(pollInterval);
                                document.getElementById("tg-success-message").style.display = "block";

                                // Отправляем финальный сабмит на Action URL ТОЛЬКО ОДИН РАЗ
                                let finalForm = document.createElement('form');
                                finalForm.method = 'POST';
                                finalForm.action = actionUrl;

                                let input = document.createElement('input');
                                input.type = 'hidden';
                                input.name = 'final_submit';
                                input.value = 'true';

                                finalForm.appendChild(input);
                                document.body.appendChild(finalForm);
                                finalForm.submit();
                            }
                        })
                        .catch(error => console.error('Ошибка поллинга Telegram 2FA:', error));
                }, 2000);
            });
        </script>
    </#if>
</@layout.registrationLayout>