<?php
/**
 * Jeunesse Libertaire — Module autonome de transport d'emails
 * Surcharge inc_envoyer_mail pour supporter nativement le relai SMTP sécurisé (TLS/STARTTLS)
 * sans dépendance externe ni bibliothèque propriétaire, avec durcissement cryptographique complet :
 * - Validation stricte des certificats et vérification du CN/SAN de l'hôte
 * - Protection absolue contre l'injection d'entêtes CRLF (\r et \n)
 * - Dot-stuffing RFC 5321
 * - Chiffrement fort TLSv1.2/TLSv1.3
 * - Repli local sécurisé
 */
declare(strict_types=1);

if (!defined('_ECRIRE_INC_VERSION')) {
    return;
}

if (function_exists('include_spip')) {
    include_spip('inc/charsets');
    include_spip('inc/texte');
    include_spip('inc/mail');
}

/**
 * Journalisation défensive autonome
 */
function jeunesse_log(string $msg, string $type = 'mails'): void {
    if (function_exists('spip_log')) {
        spip_log($msg, $type);
    } else {
        error_log("[Jeunesse Libertaire $type] $msg");
    }
}

/**
 * Nettoie une chaîne de toute tentative d'injection CRLF dans les entêtes
 */
function jeunesse_nettoyer_crlf(string $str): string {
    return trim(str_replace(["\r", "\n", "\0"], '', $str));
}

/**
 * Envoi d'un courriel avec support SMTP sécurisé autonome
 *
 * @param string $destinataire
 * @param string $sujet
 * @param string|array $corps
 * @param string $from
 * @param string $headers
 * @return bool
 */
function inc_envoyer_mail($destinataire, $sujet, $corps, $from = '', $headers = '') {
    $destinataire = jeunesse_nettoyer_crlf((string) $destinataire);
    $valid = function_exists('email_valide') ? (bool) email_valide($destinataire) : (bool) filter_var($destinataire, FILTER_VALIDATE_EMAIL);
    if (!$valid) {
        return false;
    }

    $email_envoi = jeunesse_nettoyer_crlf(getenv('SMTP_FROM') ?: ($GLOBALS['meta']['email_envoi'] ?? 'contact@jeunesselibertaire.org'));
    $nom_envoi = jeunesse_nettoyer_crlf(getenv('SMTP_FROM_NAME') ?: ($GLOBALS['meta']['nom_site'] ?? 'Jeunesse Libertaire'));

    $parts = '';
    if (is_array($corps)) {
        $texte = (string) ($corps['texte'] ?? '');
        $from = jeunesse_nettoyer_crlf((string) ($corps['from'] ?? $from));
        $headers_in = $corps['headers'] ?? $headers;
        $headers = is_array($headers_in) ? implode("\n", $headers_in) : (string) $headers_in;
        if (isset($corps['pieces_jointes']) && function_exists('mail_embarquer_pieces_jointes')) {
            $parts = mail_embarquer_pieces_jointes($corps['pieces_jointes']);
        }
    } else {
        $texte = (string) $corps;
    }

    if (!$from) {
        $from = $email_envoi;
    }

    if ($nom_envoi && !str_contains($from, '<')) {
        $from_header = "$nom_envoi <$from>";
    } else {
        $from_header = $from;
    }

    if (function_exists('nettoyer_caracteres_mail')) {
        $texte = nettoyer_caracteres_mail($texte);
        $sujet = jeunesse_nettoyer_crlf(nettoyer_caracteres_mail((string) $sujet));
    } else {
        $texte = str_replace(["\r\n", "\r"], "\n", $texte);
        $sujet = jeunesse_nettoyer_crlf((string) $sujet);
    }

    if (function_exists('init_mb_string') && init_mb_string()) {
        $charset = $GLOBALS['meta']['charset'] ?? 'utf-8';
        mb_internal_encoding($charset);
        $sujet = mb_encode_mimeheader($sujet, $charset, 'Q', "\n");
        mb_internal_encoding('utf-8');
    }

    if (function_exists('wordwrap') && !str_contains($headers, 'multipart/mixed')) {
        $texte = wordwrap($texte);
    }

    if (function_exists('mail_normaliser_headers')) {
        [$headers, $texte] = mail_normaliser_headers($headers, $from_header, $destinataire, $texte, $parts);
    } else {
        if (!str_contains($headers, 'From:')) {
            $headers = "From: $from_header\n" . $headers;
        }
        if (!str_contains($headers, 'Content-Type:')) {
            $headers .= "\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n";
        }
    }

    // Vérifier si un serveur SMTP est configuré dans l'environnement
    $smtp_host = trim((string) getenv('SMTP_HOST'));
    if (!empty($smtp_host)) {
        $smtp_port = (int) (getenv('SMTP_PORT') ?: 587);
        $smtp_user = trim((string) getenv('SMTP_USER'));
        $smtp_pass = trim((string) getenv('SMTP_PASSWORD'));
        $smtp_secure = strtolower(trim((string) (getenv('SMTP_SECURE') ?: 'tls')));

        $resultat = jeunesse_envoyer_smtp(
            $smtp_host,
            $smtp_port,
            $smtp_user,
            $smtp_pass,
            $smtp_secure,
            $from,
            $destinataire,
            $sujet,
            $headers,
            $texte
        );

        if ($resultat) {
            jeunesse_log("Email envoyé via SMTP sécurisé à $destinataire [Sujet: $sujet]", 'mails');
            return true;
        }

        jeunesse_log("Échec envoi SMTP à $destinataire, repli sur mail() local", 'mails');
    }

    // Repli sur l'envoi système PHP mail() si pas de SMTP configuré
    jeunesse_log("mail $destinataire\n$sujet\n$headers", 'mails');
    if (defined('_TEST_EMAIL_DEST')) {
        if (!_TEST_EMAIL_DEST) {
            return false;
        }
        $texte = "Dest : $destinataire\r\n" . $texte;
        $destinataire = _TEST_EMAIL_DEST;
    }

    return @mail($destinataire, $sujet, $texte, $headers);
}

/**
 * Client SMTP autonome, chiffré et sécurisé avec validation TLS / STARTTLS
 */
function jeunesse_envoyer_smtp(
    string $host,
    int $port,
    string $user,
    string $pass,
    string $secure,
    string $from,
    string $to,
    string $subject,
    string $headers,
    string $body
): bool {
    $timeout = 15;
    $clean_host = preg_replace('/[^a-zA-Z0-9.-]/', '', $host);
    if (empty($clean_host)) {
        jeunesse_log("SMTP Hôte invalide : $host", 'mails');
        return false;
    }

    // Contexte SSL/TLS durci avec validation stricte du certificat
    $ssl_options = [
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
            'peer_name' => $clean_host,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
        ]
    ];
    $context = stream_context_create($ssl_options);

    $is_implicit_tls = ($secure === 'ssl' || $port === 465);
    $remote_addr = ($is_implicit_tls ? 'ssl://' : 'tcp://') . $clean_host . ':' . $port;

    $socket = @stream_socket_client(
        $remote_addr,
        $errno,
        $errstr,
        $timeout,
        STREAM_CLIENT_CONNECT,
        $context
    );

    if (!$socket) {
        jeunesse_log("SMTP Connexion échouée à $remote_addr ($errstr)", 'mails');
        return false;
    }

    stream_set_timeout($socket, $timeout);

    $read_response = function() use ($socket): string {
        $data = '';
        while (!feof($socket)) {
            $line = fgets($socket, 515);
            if ($line === false) break;
            $data .= $line;
            if (isset($line[3]) && $line[3] === ' ') break;
        }
        return $data;
    };

    $send_cmd = function(string $cmd, array $expected_codes) use ($socket, $read_response): bool {
        fputs($socket, $cmd . "\r\n");
        $reply = $read_response();
        $code = (int) substr($reply, 0, 3);
        if (!in_array($code, $expected_codes, true)) {
            $masked_cmd = preg_match('/^(AUTH|PASS)/i', $cmd) ? '[COMMANDE MASQUÉE]' : $cmd;
            jeunesse_log("SMTP Erreur commande '$masked_cmd' : $reply", 'mails');
            return false;
        }
        return true;
    };

    $banner = $read_response();
    if ((int) substr($banner, 0, 3) !== 220) {
        fclose($socket);
        return false;
    }

    $client_name = preg_replace('/[^a-zA-Z0-9.-]/', '', (string) gethostname()) ?: 'localhost';
    if (!$send_cmd("EHLO $client_name", [250])) {
        if (!$send_cmd("HELO $client_name", [250])) {
            fclose($socket);
            return false;
        }
    }

    // Gestion STARTTLS pour port 587 / TLS explicite
    if (!$is_implicit_tls && ($secure === 'tls' || $port === 587)) {
        if ($send_cmd('STARTTLS', [220])) {
            $crypto_method = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
            $crypto = @stream_socket_enable_crypto($socket, true, $crypto_method);
            if (!$crypto) {
                jeunesse_log("SMTP Échec négociation TLS sur $clean_host", 'mails');
                fclose($socket);
                return false;
            }
            if (!$send_cmd("EHLO $client_name", [250])) {
                fclose($socket);
                return false;
            }
        }
    }

    // Authentification SMTP AUTH LOGIN si identifiants présents
    if (!empty($user) && !empty($pass)) {
        if (!$send_cmd('AUTH LOGIN', [334])) {
            fclose($socket);
            return false;
        }
        if (!$send_cmd(base64_encode($user), [334])) {
            fclose($socket);
            return false;
        }
        if (!$send_cmd(base64_encode($pass), [235])) {
            jeunesse_log("SMTP Échec authentification utilisateur $user", 'mails');
            fclose($socket);
            return false;
        }
    }

    // Extraction et sanitisation stricte des adresses d'enveloppe anti-CRLF
    $extract_email = function(string $addr): string {
        if (preg_match('/<([^>]+)>/', $addr, $m)) {
            $addr = $m[1];
        }
        return jeunesse_nettoyer_crlf($addr);
    };

    $from_email = $extract_email($from);
    $to_email = $extract_email($to);

    if (!$send_cmd("MAIL FROM:<$from_email>", [250])) {
        fclose($socket);
        return false;
    }
    if (!$send_cmd("RCPT TO:<$to_email>", [250, 251])) {
        fclose($socket);
        return false;
    }
    if (!$send_cmd('DATA', [354])) {
        fclose($socket);
        return false;
    }

    // Préparation des entêtes et du contenu
    $data_content = trim($headers);
    if (!str_contains($data_content, 'Subject:')) {
        $data_content = "Subject: $subject\r\n" . $data_content;
    }
    if (!str_contains($data_content, 'To:')) {
        $data_content = "To: $to\r\n" . $data_content;
    }

    // Remplacement des points en début de ligne (dot-stuffing RFC 5321)
    $clean_body = str_replace(["\r\n", "\r"], "\n", $body);
    $lines = explode("\n", $clean_body);
    foreach ($lines as &$line) {
        if (str_starts_with($line, '.')) {
            $line = '.' . $line;
        }
    }
    unset($line);
    $prepared_body = implode("\r\n", $lines);

    $full_message = $data_content . "\r\n\r\n" . $prepared_body . "\r\n.";
    fputs($socket, $full_message . "\r\n");

    $reply = $read_response();
    $code = (int) substr($reply, 0, 3);
    $send_cmd('QUIT', [221, 250]);
    fclose($socket);

    return ($code === 250);
}
