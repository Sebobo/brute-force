<?php
namespace AE\BruteForce\Aspects;

use GuzzleHttp\Psr7\ServerRequest;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Aop\JoinPointInterface;
use Neos\Flow\Security\Account;
use Neos\SwiftMailer\Message;

/**
 * Advice the Account to deactivate if failed attempts threshold is exceeded
 *
 * @Flow\Aspect
 * @Flow\Scope("singleton")
 */
class AccountAspect {

    /**
     * @var array
     */
    protected $settings;

    /**
     * @param array $settings
     * @return void
     */
    public function injectSettings(array $settings)
    {
        $this->settings = $settings;
    }

    /**
     * @Flow\AfterReturning("method(Neos\Flow\Security\Account->authenticationAttempted())")
     */
    public function bruteForceAccountLocking(JoinPointInterface $joinPoint): void
    {
        $failedAttemptsThreshold = (int)$this->settings['failedAttemptsThreshold'];
        if ($failedAttemptsThreshold === 0) {
            return;
        }

        /** @var Account $account */
        $account = $joinPoint->getProxy();

        // Deactivate account if failed attempts exceed threshold
        if ($account->getFailedAuthenticationCount() >= $failedAttemptsThreshold) {
            $account->setExpirationDate(new \DateTime());
            $this->sendNotificationMail($account);
        }
    }

    protected function sendNotificationMail(Account $account): void
    {
        $notificationMailSettings = $this->settings['notificationMail'];
        if (!$notificationMailSettings['to']) {
            return;
        }
        $uri = ServerRequest::getUriFromGlobals();
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $failedAttemptsThreshold = $this->settings['failedAttemptsThreshold'];
        $time = (new \DateTime())->format('Y-m-d H:i');

        $replacePlaceholders = static function($string) use ($account, $uri, $clientIp, $failedAttemptsThreshold, $time) {
            return str_replace([
                '{domain}', '{ip}', '{userAgent}', '{accountIdentifier}', '{failedAttemptsThreshold}', '{time}'
            ], [
                $uri->getHost(),
                $clientIp,
                $_SERVER['HTTP_USER_AGENT'],
                $account->getAccountIdentifier(),
                $failedAttemptsThreshold,
                $time
            ], $string);
        };

        $mail = new Message();
        $mail
            ->setFrom(
                $replacePlaceholders($notificationMailSettings['from']['email']),
                $replacePlaceholders($notificationMailSettings['from']['name'])
            )
            ->setTo($notificationMailSettings['to'])
            ->setSubject($replacePlaceholders($notificationMailSettings['subject']))
            ->setBody($replacePlaceholders($notificationMailSettings['message']))
            ->send();
    }

}
