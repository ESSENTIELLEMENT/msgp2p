<?php
declare(strict_types=1);

namespace MsgP2P\Server;

use Throwable;
use InvalidArgumentException;

class Router {
    public static function dispatch(?string $method = null, ?string $uri = null, ?string $body = null): void {
        $method = $method ?? $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $uri = $uri ?? $_SERVER['REQUEST_URI'] ?? '/';
        
        $path = parse_url($uri, PHP_URL_PATH);
        if (str_starts_with($path, '/api/v1')) {
            $path = substr($path, 7);
        }

        if ($method === 'OPTIONS') {
            self::setResponseCode(204);
            self::setHeader('Access-Control-Allow-Origin: *');
            self::setHeader('Access-Control-Allow-Methods: GET, POST, OPTIONS');
            self::setHeader('Access-Control-Allow-Headers: Content-Type, Authorization');
            exit;
        }

        self::setHeader('Content-Type: application/json; charset=utf-8');
        self::setHeader('Access-Control-Allow-Origin: *');

        try {
            $controller = new GatewayController();
            $auth = self::getAuth();

            $isProtected = in_array($path, ['/sync/push', '/sync/pull', '/sync/receipts', '/sync/revocations', '/sync/attachments'], true);
            if ($isProtected && $auth === null) {
                self::setResponseCode(401);
                echo json_encode(['error' => 'UNAUTHORIZED', 'message' => 'Missing or invalid authentication token']);
                return;
            }

            if ($method === 'POST' && $path === '/auth/register') {
                $rawInput = $body ?? file_get_contents('php://input');
                $data = json_decode($rawInput, true) ?? [];
                $res = $controller->register($data);
                self::setResponseCode(200);
                echo json_encode($res);
                return;
            }

            if ($method === 'POST' && $path === '/auth/login') {
                $rawInput = $body ?? file_get_contents('php://input');
                $data = json_decode($rawInput, true) ?? [];
                $res = $controller->login($data);
                self::setResponseCode(200);
                echo json_encode($res);
                return;
            }

            if ($method === 'POST' && $path === '/sync/push') {
                $rawInput = $body ?? file_get_contents('php://input');
                $data = json_decode($rawInput, true) ?? [];
                $res = $controller->push($data);
                self::setResponseCode(200);
                echo json_encode($res);
                return;
            }

            if ($method === 'GET' && $path === '/sync/pull') {
                $groupId = (string)($_GET['group_id'] ?? '');
                $vector = (string)($_GET['vector'] ?? '');
                $limit = (int)($_GET['limit'] ?? 100);
                if (empty($groupId)) {
                    self::setResponseCode(400);
                    echo json_encode(['error' => 'BAD_REQUEST', 'message' => 'group_id parameter is required']);
                    return;
                }
                $res = $controller->pull($groupId, $vector, $limit);
                self::setResponseCode(200);
                echo json_encode($res);
                return;
            }

            if ($method === 'GET' && $path === '/sync/receipts') {
                $groupId = (string)($_GET['group_id'] ?? '');
                $since = (int)($_GET['since'] ?? 0);
                if (empty($groupId)) {
                    self::setResponseCode(400);
                    echo json_encode(['error' => 'BAD_REQUEST', 'message' => 'group_id parameter is required']);
                    return;
                }
                $res = $controller->receipts($groupId, $since);
                self::setResponseCode(200);
                echo json_encode($res);
                return;
            }

            if ($method === 'GET' && $path === '/sync/revocations') {
                $groupId = (string)($_GET['group_id'] ?? '');
                $since = (int)($_GET['since'] ?? 0);
                if (empty($groupId)) {
                    self::setResponseCode(400);
                    echo json_encode(['error' => 'BAD_REQUEST', 'message' => 'group_id parameter is required']);
                    return;
                }
                $res = $controller->revocations($groupId, $since);
                self::setResponseCode(200);
                echo json_encode($res);
                return;
            }

            if ($method === 'POST' && $path === '/sync/revocations') {
                $rawInput = $body ?? file_get_contents('php://input');
                $data = json_decode($rawInput, true) ?? [];
                $res = $controller->revokeMember($data);
                self::setResponseCode(200);
                echo json_encode($res);
                return;
            }

            if ($method === 'POST' && $path === '/sync/attachments') {
                $rawInput = $body ?? file_get_contents('php://input');
                $data = json_decode($rawInput, true) ?? [];
                $res = $controller->uploadAttachment($data);
                self::setResponseCode(200);
                echo json_encode($res);
                return;
            }

            if ($method === 'GET' && $path === '/sync/attachments') {
                $groupId = (string)($_GET['group_id'] ?? '');
                $hash = (string)($_GET['hash'] ?? '');
                if (empty($groupId) || empty($hash)) {
                    self::setResponseCode(400);
                    echo json_encode(['error' => 'BAD_REQUEST', 'message' => 'group_id and hash parameters are required']);
                    return;
                }
                $res = $controller->getAttachment($groupId, $hash);
                self::setResponseCode(200);
                echo json_encode($res);
                return;
            }

            self::setResponseCode(404);
            echo json_encode(['error' => 'NOT_FOUND', 'message' => "Route $method $path not found"]);
        } catch (InvalidArgumentException $e) {
            self::setResponseCode(400);
            echo json_encode(['error' => 'BAD_REQUEST', 'message' => $e->getMessage()]);
        } catch (Throwable $e) {
            $code = (int)$e->getCode();
            $status = ($code >= 400 && $code < 600) ? $code : 500;
            self::setResponseCode($status);
            echo json_encode(['error' => $status === 401 ? 'UNAUTHORIZED' : 'INTERNAL_ERROR', 'message' => $e->getMessage()]);
        }
    }

    private static function setResponseCode(int $code): void {
        if (!headers_sent()) {
            http_response_code($code);
        }
    }

    private static function setHeader(string $header): void {
        if (!headers_sent()) {
            header($header);
        }
    }

    private static function getAuth(): ?array {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if (empty($authHeader) && function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
        }

        if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return Auth::verifyToken(trim($matches[1]));
        }

        return null;
    }
}
