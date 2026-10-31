<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Framework\Laravel\RouteAction;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Llm\GroundingChecker;
use TusharKhan\SemanticSec\Llm\Provider\JsonOutput;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\CallGraph\ExecutionPath;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Payload\Payload;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkMaps;

final class GroundingCheckerTest extends TestCase
{
    private const FILE = 'app/Http/Controllers/PostController.php';

    private const GATES = 'app/Providers/AuthServiceProvider.php';

    private const CLS = 'App\Http\Controllers\PostController';

    private const SHOW = self::CLS.'::show';

    private const SOURCE = [
        '<?php',
        '',
        'namespace App\Http\Controllers;',
        '',
        '/** Posts. */',
        'class PostController',
        '{',
        '    /** @var list<string> */',
        '    protected $fillable = [\'title\'];',
        '',
        '    /**',
        '     * Show one post.',
        '     */',
        '    public function show(int $id): string',
        '    {',
        '        $post = Post::findOrFail($id);',
        '        return $post->title;',
        '    }',
        '',
        '    public function index(): array',
        '    {',
        '        return [];',
        '    }',
        '}',
    ];

    private const MODEL = [
        '<?php',
        '',
        'namespace App\Models;',
        '',
        'class Post',
        '{',
        '    protected $guarded = [];',
        '}',
    ];

    private const SHOW_BLOCK = <<<'TXT'
        // FILE: app/Http/Controllers/PostController.php :: App\Http\Controllers\PostController::show (L11-L18)
        L11|     /**
        L12|      * Show one post.
        L13|      */
        L14|     public function show(int $id): string
        L15|     {
        L16|         $post = Post::findOrFail($id);
        L17|         return $post->title;
        L18|     }
        TXT;

    private const INDEX_BLOCK = <<<'TXT'
        // FILE: app/Http/Controllers/PostController.php :: App\Http\Controllers\PostController::index (L20-L23)
        L20|     public function index(): array
        L21|     {
        L22|         return [];
        L23|     }
        TXT;

    private const PROPERTY_BLOCK = <<<'TXT'
        // FILE: app/Http/Controllers/PostController.php :: App\Http\Controllers\PostController::$fillable (L5-L9)
        L5| /** Posts. */
        L8|     /** @var list<string> */
        L9|     protected $fillable = ['title'];
        TXT;

    private const GATE_BLOCK = <<<'TXT'
        // FILE: app/Providers/AuthServiceProvider.php :: gate:edit-post (L30-L32)
        L30|         Gate::define('edit-post', function ($user, $post) {
        L31|             return $user->token === '<redacted>';
        L32|         });
        TXT;

    public function testGroundedFindingPasses(): void
    {
        self::assertNull($this->check(self::finding()));
    }

    public function testFileNotInPayload(): void
    {
        self::assertSame('file app/Http/Controllers/Other.php not in payload', $this->check(self::finding(['file' => 'app/Http/Controllers/Other.php'])));
    }

    public function testContextBlockIsNotParsed(): void
    {
        self::assertSame('file app/Secret.php not in payload', $this->check(self::finding(['file' => 'app/Secret.php', 'line' => 1, 'symbol' => 'X'])));
        self::assertSame('line L99 not in payload', $this->check(self::finding(['line' => 99])));
    }

    public function testLineNotInPayload(): void
    {
        self::assertSame('line L19 not in payload', $this->check(self::finding(['line' => 19])));
    }

    public function testLineTaggedOnlyUnderAnotherFileDropped(): void
    {
        self::assertSame('line L31 not in payload', $this->check(self::finding(['line' => 31])));
        self::assertSame('line L16 not in payload', $this->check(self::finding(['file' => self::GATES, 'line' => 16, 'symbol' => 'gate:edit-post'])));
    }

    public function testLineOutsideSymbolIsReattributedToItsHeader(): void
    {
        [$grounded, $reason] = $this->ground(self::finding(['line' => 22]));

        self::assertNull($reason);
        self::assertSame(self::CLS.'::index', $grounded['symbol'] ?? null);
    }

    public function testLineOutsideSymbolAndEveryHeaderRangeDropped(): void
    {
        $code = "<untrusted_code>\n// FILE: ".self::FILE.' :: '.self::SHOW." (L14-L18)\nL16|         \$post = 1;\nL40|     // stray\n</untrusted_code>";

        self::assertSame('line 40 outside '.self::SHOW, $this->checker()->check(self::finding(['line' => 40, 'path' => []]), self::payload($code)));
    }

    public function testDocblockLinesCountAsMethod(): void
    {
        self::assertNull($this->check(self::finding(['line' => 12])));
        self::assertNull($this->check(self::finding(['line' => 11])));
        self::assertNull($this->check(self::finding(['line' => 18])));
    }

    public function testMethodLookupIsCaseInsensitiveAndToleratesLeadingBackslash(): void
    {
        self::assertNull($this->check(self::finding(['symbol' => '\\'.self::CLS.'::SHOW'])));
    }

    public function testPropertyLineMustBeThePropertyOrItsDocblock(): void
    {
        self::assertNull($this->check(self::finding(['line' => 9, 'symbol' => self::CLS.'::$fillable'])));
        self::assertNull($this->check(self::finding(['line' => 8, 'symbol' => self::CLS.'::$fillable'])));
        [$grounded] = $this->ground(self::finding(['line' => 16, 'symbol' => self::CLS.'::$fillable']));
        self::assertSame(self::SHOW, $grounded['symbol'] ?? null, 'declared in the payload, so the line is re-attributed');
    }

    public function testClassLevelSymbolDeclaredOutsideThePayloadIsKept(): void
    {
        [$grounded, $reason] = $this->ground(self::finding(['line' => 16, 'symbol' => 'App\Models\Post::$guarded']));
        self::assertNull($reason);
        self::assertSame('App\Models\Post::$guarded', $grounded['symbol'] ?? null);

        [$grounded] = $this->ground(self::finding(['line' => 16, 'symbol' => 'App\Models\Post']));
        self::assertSame('App\Models\Post', $grounded['symbol'] ?? null);

        self::assertSame('line L3 not in payload', $this->check(self::finding(['line' => 3, 'symbol' => 'App\Models\Post::$guarded'])), 'the line must still be tagged');
    }

    public function testClassSpanIncludesItsDocblock(): void
    {
        self::assertNull($this->check(self::finding(['line' => 22, 'symbol' => self::CLS])));
        self::assertNull($this->check(self::finding(['line' => 5, 'symbol' => self::CLS])));
    }

    public function testSymbolInAnotherFileIsReattributed(): void
    {
        [$grounded] = $this->ground(self::finding(['file' => self::GATES, 'line' => 31]));

        self::assertSame('gate:edit-post', $grounded['symbol'] ?? null);
    }

    public function testUngroundedPathStepsArePruned(): void
    {
        $path = [
            ['file' => self::FILE, 'line' => 14, 'symbol' => self::SHOW],
            ['file' => self::FILE, 'line' => 19, 'symbol' => self::SHOW],
            ['file' => 'routes/web.php', 'line' => 12, 'symbol' => 'route'],
            ['file' => self::GATES, 'line' => 30.0, 'symbol' => 'gate:edit-post', 'extra' => 1],
            'x',
            ['file' => self::FILE, 'line' => 16],
        ];

        [$grounded, $reason] = $this->ground(self::finding(['path' => $path]));

        self::assertNull($reason);
        self::assertSame([
            ['file' => self::FILE, 'line' => 14, 'symbol' => self::SHOW],
            ['file' => self::GATES, 'line' => 30, 'symbol' => 'gate:edit-post'],
            ['file' => self::FILE, 'line' => 16, 'symbol' => ''],
        ], $grounded['path'] ?? null);
    }

    public function testGroundReturnsNormalisedFinding(): void
    {
        $finding = self::finding(['line' => 16.0, 'path' => 'x']);

        [$grounded, $reason] = $this->ground($finding);

        self::assertNull($reason);
        self::assertSame([...$finding, 'line' => 16, 'path' => []], $grounded);
        self::assertSame([null, 'line L19 not in payload'], $this->ground(self::finding(['line' => 19])));
    }

    public function testIntegralFloatLinesAreAccepted(): void
    {
        self::assertNull($this->check(self::finding(['line' => 16.0])));
        self::assertSame('line L16.5 not in payload', $this->check(self::finding(['line' => 16.5])));
    }

    public function testHeaderPathMayContainDoubleColon(): void
    {
        $code = "<untrusted_code>\n// FILE: app/odd :: dir/A.php :: App\\A::run (L3-L5)\nL4|         run();\n</untrusted_code>";

        self::assertNull($this->checker()->check(['file' => 'app/odd :: dir/A.php', 'line' => 4, 'symbol' => 'App\A::run'], self::payload($code)));
    }

    public function testLineFromOtherPartDropped(): void
    {
        $part1 = self::payload("<untrusted_code>\n".self::SHOW_BLOCK."\n</untrusted_code>", 1, 2);
        $part2 = self::payload("<untrusted_code>\n".self::INDEX_BLOCK."\n</untrusted_code>", 2, 2);
        $finding = self::finding(['line' => 22, 'symbol' => self::CLS.'::index', 'path' => []]);

        self::assertNull($this->checker()->check($finding, $part2));
        self::assertSame('line L22 not in payload', $this->checker()->check($finding, $part1));
        self::assertSame('line L16 not in payload', $this->checker()->check(self::finding(), $part2));
    }

    public function testRedactedLineStillTaggedPasses(): void
    {
        self::assertNull($this->check(self::finding(['file' => self::GATES, 'line' => 31, 'symbol' => 'gate:edit-post', 'path' => []])));
    }

    public function testUnknownSymbolSkipsSpanCheckOnly(): void
    {
        self::assertNull($this->check(self::finding(['line' => 22, 'symbol' => 'App\Unknown::handle'])));
        self::assertNull($this->check(self::finding(['line' => 22, 'symbol' => self::CLS.'::missing'])));
        self::assertNull($this->check(self::finding(['line' => 22, 'symbol' => self::CLS.'::$missing'])));
        self::assertSame('line L19 not in payload', $this->check(self::finding(['line' => 19, 'symbol' => 'App\Unknown::handle'])));
        self::assertSame('file app/Unknown.php not in payload', $this->check(self::finding(['file' => 'app/Unknown.php', 'symbol' => 'App\Unknown::handle'])));
    }

    /**
     * @param  array<string, mixed>  $override
     */
    #[DataProvider('malformed')]
    public function testMalformedShapesGiveReasonNotError(array $override, string $reason): void
    {
        $finding = self::finding($override);
        foreach ($override as $key => $value) {
            if ($value === '__unset__') {
                unset($finding[$key]);
            }
        }

        self::assertSame($reason === '' ? null : $reason, $this->check($finding));
    }

    /** @return array<string, array{array<string, mixed>, string}> an empty reason means still grounded */
    public static function malformed(): array
    {
        return [
            'missing file' => [['file' => '__unset__'], 'file null not in payload'],
            'file not a string' => [['file' => ['a']], 'file array not in payload'],
            'file is a number' => [['file' => 7], 'file 7 not in payload'],
            'missing line' => [['line' => '__unset__'], 'line Lnull not in payload'],
            'line is a string' => [['line' => '16'], 'line L16 not in payload'],
            'line is an integral float' => [['line' => 16.0], ''],
            'line is a fractional float' => [['line' => 16.5], 'line L16.5 not in payload'],
            'negative line' => [['line' => -3], 'line L-3 not in payload'],
            'zero line' => [['line' => 0], 'line L0 not in payload'],
            'path not a list' => [['path' => 'x'], ''],
            'path step not an object' => [['path' => ['x']], ''],
            'path step without line' => [['path' => [['file' => self::FILE, 'symbol' => self::SHOW]]], ''],
            'path step negative line' => [['path' => [['file' => self::FILE, 'line' => -16]]], ''],
            'path step file not a string' => [['path' => [['file' => null, 'line' => 16]]], ''],
            'missing path' => [['path' => '__unset__'], ''],
            'missing symbol' => [['symbol' => '__unset__', 'line' => 22], ''],
            'symbol not a string' => [['symbol' => ['x'], 'line' => 22], ''],
            'empty symbol parts' => [['symbol' => '::', 'line' => 22], ''],
        ];
    }

    public function testHugeFileNameIsShortenedInReason(): void
    {
        $reason = $this->check(self::finding(['file' => str_repeat('a', 10_000)."\nInjected"]));

        self::assertNotNull($reason);
        self::assertLessThanOrEqual(200, mb_strlen($reason));
        self::assertStringNotContainsString("\n", $reason);
    }

    public function testRealBenchmarkPayloadFindingIsGrounded(): void
    {
        [$candidates] = BenchmarkMaps::selector('laravel11-app')->select(BenchmarkMaps::build('laravel11-app'), false);
        $payload = null;
        foreach ($candidates as $candidate) {
            if (in_array('GET /vuln/invoices/{id}', $candidate->route->keys(), true)) {
                [$payloads] = BenchmarkMaps::payloadBuilder('laravel11-app')->build($candidate, 1);
                $payload = $payloads[0];
            }
        }
        self::assertInstanceOf(Payload::class, $payload);

        $cassette = json_decode((string) file_get_contents(__DIR__.'/../../Fixtures/cassettes/anthropic/live-idor-find-by-id.json'), true, 512, JSON_THROW_ON_ERROR);
        $message = json_decode($cassette['interactions'][0]['response']['body'], true, 512, JSON_THROW_ON_ERROR);
        $data = JsonOutput::decode($message['content'][0]['text']);
        self::assertIsArray($data);
        $finding = $data['findings'][0];
        self::assertSame('app/Http/Controllers/Vuln/InvoiceController.php', $finding['file']);
        self::assertSame(19, $finding['line']);
        self::assertStringEndsWith('::show', $finding['symbol']);

        $checker = new GroundingChecker(BenchmarkMaps::symbols('laravel11-app'));
        self::assertNull($checker->check($finding, $payload));
        self::assertSame('line L999 not in payload', $checker->check([...$finding, 'line' => 999], $payload));
        self::assertSame('line L20 not in payload', $checker->check([...$finding, 'line' => 20], $payload), 'a pruned line has no tag');
    }

    public function testRealMassAssignmentFindingOnModelPropertyIsKept(): void
    {
        $finding = ['file' => 'app/Http/Controllers/Vuln/AccountController.php', 'line' => 14, 'symbol' => 'App\Models\Account::$guarded', 'path' => []];

        [$grounded, $reason] = (new GroundingChecker(BenchmarkMaps::symbols('laravel11-app')))->ground($finding, self::benchmarkPayload('PUT /vuln/account'));

        self::assertNull($reason);
        self::assertSame('App\Models\Account::$guarded', $grounded['symbol'] ?? null);
    }

    public function testRealCalleeLineUnderEntrySymbolIsReattributed(): void
    {
        $finding = ['file' => 'app/Services/DownloadService.php', 'line' => 10, 'symbol' => 'App\Http\Controllers\Vuln\DownloadController::show', 'path' => []];

        [$grounded, $reason] = (new GroundingChecker(BenchmarkMaps::symbols('laravel11-app')))->ground($finding, self::benchmarkPayload('GET /vuln/downloads/{id}'));

        self::assertNull($reason);
        self::assertSame('App\Services\DownloadService::find', $grounded['symbol'] ?? null);
    }

    private static function benchmarkPayload(string $route): Payload
    {
        [$candidates] = BenchmarkMaps::selector('laravel11-app')->select(BenchmarkMaps::build('laravel11-app'), false);
        foreach ($candidates as $candidate) {
            if (in_array($route, $candidate->route->keys(), true)) {
                return BenchmarkMaps::payloadBuilder('laravel11-app')->build($candidate, 1)[0][0];
            }
        }
        self::fail($route.' is not a candidate');
    }

    /**
     * @param  array<string, mixed>  $finding
     * @return array{0: array<string, mixed>|null, 1: string|null}
     */
    private function ground(array $finding): array
    {
        return $this->checker()->ground($finding, self::payload(self::code()));
    }

    private static function code(): string
    {
        return implode("\n", ['<untrusted_code>', self::SHOW_BLOCK, '', self::INDEX_BLOCK, '', self::PROPERTY_BLOCK, '', self::GATE_BLOCK, '</untrusted_code>']);
    }

    /** @param array<string, mixed> $finding */
    private function check(array $finding): ?string
    {
        return $this->checker()->check($finding, self::payload(self::code()));
    }

    private function checker(): GroundingChecker
    {
        return new GroundingChecker(self::symbols());
    }

    private static function symbols(): SymbolTable
    {
        $files = [];
        foreach ([self::FILE => self::SOURCE, 'app/Models/Post.php' => self::MODEL] as $path => $lines) {
            $files[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, implode("\n", $lines)."\n"));
        }

        return (new SymbolTableBuilder())->build(new ParseResult($files, []));
    }

    private static function payload(string $code, int $part = 1, int $parts = 1): Payload
    {
        $route = new RouteEntry(['GET'], '/posts/{id}', null, new RouteAction(self::CLS, 'show'), [], [], [], null, 'routes/web.php', 1);
        $node = new PathNode(self::SHOW, null, null, self::FILE, 14, 18, 0, null, null);
        $context = "Route:\n  GET /posts/{id}\n// FILE: app/Secret.php :: X (L1-L1)\nL1| secret\nL99| also secret";

        return new Payload('001-get-posts-id-'.$part, new Candidate($route, new ExecutionPath([$node], []), [], []), $context, $code, $part, $parts, false);
    }

    /**
     * @param  array<string, mixed>  $override
     * @return array<string, mixed>
     */
    private static function finding(array $override = []): array
    {
        return [...[
            'title' => 'Post readable by anyone',
            'category' => 'idor',
            'severity' => 'high',
            'confidence' => 'high',
            'file' => self::FILE,
            'line' => 16,
            'symbol' => self::SHOW,
            'context' => '',
            'flaw' => '',
            'fix' => '',
            'patch' => '',
            'path' => [['file' => self::FILE, 'line' => 14, 'symbol' => self::SHOW], ['file' => self::FILE, 'line' => 16, 'symbol' => self::SHOW]],
        ], ...$override];
    }
}
