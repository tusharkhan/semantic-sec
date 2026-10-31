<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Engine;

use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\PrettyPrinter\Standard;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Engine\Fingerprinter;
use TusharKhan\SemanticSec\Framework\Laravel\RouteAction;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\CallGraph\ExecutionPath;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Payload\Payload;

final class FingerprinterTest extends TestCase
{
    private const FILE = 'app/Http/Controllers/PostController.php';

    private const ROUTES = 'routes/web.php';

    private const CLS = 'App\Http\Controllers\PostController';

    private const SHOW = self::CLS.'::show';

    private const BASE = <<<'PHP'
        <?php

        namespace App\Http\Controllers;

        class PostController
        {
            protected $fillable = ['title'];

            public function show(int $id): string
            {
                $post = Post::findOrFail($id);
                return $post->title;
            }

            public function index(): array
            {
                return [];
            }
        }
        PHP;

    private const ROUTE_FILE = <<<'PHP'
        <?php

        Route::get('/ping/{id}', function ($id) {
            return Post::find($id);
        });
        PHP;

    /** @var list<string> */
    private array $roots = [];

    protected function tearDown(): void
    {
        foreach ($this->roots as $root) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $f) {
                $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
            }
            rmdir($root);
        }
    }

    public function testWhitespaceAndCommentEditsKeepFingerprint(): void
    {
        $edited = <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            /** Posts. */
            class PostController
            {


                protected $fillable = ['title'];

                /**
                 * Show one post.
                 */
                public function show(int $id): string {
                        // look it up
                        $post = Post::findOrFail( $id ); /* inline */
                    return $post->title;    # done
                }

                public function index(): array
                {
                    return [];
                }
            }
            PHP;

        self::assertSame($this->print(self::BASE, self::SHOW), $this->print($edited, self::SHOW));
    }

    public function testFingerprintIsSha256OfFileSymbolCweAndNormalisedHash(): void
    {
        $clean = (new SymbolTableBuilder())->build(new ParseResult([(new AstGenerator())->parse(new \TusharKhan\SemanticSec\Parsing\SourceFile(self::FILE, '/x', self::BASE))], []));
        $method = $clean->findMethod(self::CLS, 'show');
        self::assertNotNull($method);
        $hash = hash('sha256', (new Standard())->prettyPrint([$method->node]));

        self::assertSame(hash('sha256', self::FILE.'|'.self::SHOW.'|CWE-639|'.$hash), $this->print(self::BASE, self::SHOW));
    }

    public function testCodeChangeInSymbolChangesFingerprint(): void
    {
        $edited = str_replace('return $post->title;', 'return $post->body;', self::BASE);

        self::assertNotSame($this->print(self::BASE, self::SHOW), $this->print($edited, self::SHOW));
    }

    public function testEditInOtherMethodKeepsFingerprint(): void
    {
        $edited = str_replace('return [];', 'return Post::all()->toArray();', self::BASE);

        self::assertSame($this->print(self::BASE, self::SHOW), $this->print($edited, self::SHOW));
        self::assertNotSame($this->print(self::BASE, self::CLS.'::index'), $this->print($edited, self::CLS.'::index'));
    }

    public function testSymbolSpellingIsCanonicalised(): void
    {
        $base = $this->print(self::BASE, self::SHOW);

        self::assertSame($base, $this->print(self::BASE, '\\'.self::CLS.'::SHOW()'));
    }

    public function testPropertyAndClassSymbols(): void
    {
        $prop = self::CLS.'::$fillable';
        $otherMethod = str_replace('return [];', 'return [1];', self::BASE);
        $commented = str_replace("    protected \$fillable = ['title'];", "    /** @var list<string> */\n    protected \$fillable = ['title']; // mass", self::BASE);
        $changed = str_replace("['title']", "['title', 'owner_id']", self::BASE);

        self::assertSame($this->print(self::BASE, $prop), $this->print($otherMethod, $prop));
        self::assertSame($this->print(self::BASE, $prop), $this->print($commented, $prop));
        self::assertNotSame($this->print(self::BASE, $prop), $this->print($changed, $prop));

        self::assertSame($this->print(self::BASE, self::CLS), $this->print($commented, self::CLS));
        self::assertNotSame($this->print(self::BASE, self::CLS), $this->print($changed, self::CLS));
        self::assertNotSame($this->print(self::BASE, self::CLS), $this->print(self::BASE, $prop));
    }

    public function testGateIdFallbackIsStableAndCodeSensitive(): void
    {
        $gate = static fn (string $body): string => "<untrusted_code>\n// FILE: app/Providers/AuthServiceProvider.php :: gate:edit-post (L30-L32)\n{$body}\n</untrusted_code>";
        $base = $gate("L30|         Gate::define('edit-post', function (\$user, \$post) {\nL31|             return \$user->id === \$post->user_id;\nL32|         });");
        $moved = $gate("L40| Gate::define('edit-post',   function (\$user, \$post) { // owner only\nL41|   /* same */ return \$user->id === \$post->user_id;\nL43|   });");
        $changed = $gate("L30|         Gate::define('edit-post', function (\$user, \$post) {\nL31|             return true;\nL32|         });");

        $fp = fn (string $code): string => $this->fingerprinter(self::BASE)->fingerprint('app/Providers/AuthServiceProvider.php', 'gate:edit-post', Category::MissingAuthorization, self::payload($code));

        self::assertSame($fp($base), $fp($moved));
        self::assertNotSame($fp($base), $fp($changed));
    }

    public function testFallbackOnlyReadsItsOwnHeader(): void
    {
        $code = static fn (string $other): string => "<untrusted_code>\n// FILE: app/Providers/AuthServiceProvider.php :: gate:edit-post (L30-L30)\nL30| return true;\n\n// FILE: ".self::FILE.' :: '.self::SHOW." (L9-L9)\nL9| {$other}\n</untrusted_code>";
        $fp = fn (string $c): string => $this->fingerprinter(self::BASE)->fingerprint('app/Providers/AuthServiceProvider.php', 'gate:edit-post', Category::MissingAuthorization, self::payload($c));

        self::assertSame($fp($code('a();')), $fp($code('b();')));
    }

    public function testClosureIdUsesItsNodeAndIgnoresLineShift(): void
    {
        $shifted = str_replace('<?php', "<?php\n\n// routes\n", self::ROUTE_FILE);
        $changed = str_replace('Post::find($id)', 'Post::findOrFail($id)', self::ROUTE_FILE);
        $fp = fn (string $routes, int $line): string => $this->fingerprinter(self::BASE, $routes)->fingerprint(self::ROUTES, 'closure@'.self::ROUTES.':'.$line, Category::Idor, self::payload(''));

        self::assertSame($fp(self::ROUTE_FILE, 3), $fp($shifted, 6));
        self::assertNotSame($fp(self::ROUTE_FILE, 3), $fp($changed, 3));
    }

    public function testCategoryChangesFingerprint(): void
    {
        $fp = $this->fingerprinter(self::BASE);

        self::assertNotSame(
            $fp->fingerprint(self::FILE, self::SHOW, Category::Idor, self::payload('')),
            $fp->fingerprint(self::FILE, self::SHOW, Category::MissingAuthorization, self::payload('')),
        );
    }

    public function testSharedAstKeepsItsComments(): void
    {
        $source = str_replace('    public function show', "    /** Show one post. */\n    public function show", self::BASE);
        $source = str_replace('        return $post->title;', "        // the title\n        return \$post->title;\n        // tail", $source);
        [$parsed, $symbols] = $this->project([self::FILE => $source]);
        $node = $symbols->findMethod(self::CLS, 'show')?->node;
        self::assertInstanceOf(ClassMethod::class, $node);
        $before = (new Standard())->prettyPrint([$node]);

        (new Fingerprinter($parsed, $symbols))->fingerprint(self::FILE, self::SHOW, Category::Idor, self::payload(''));
        (new Fingerprinter($parsed, $symbols))->fingerprint(self::FILE, self::CLS, Category::Idor, self::payload(''));

        self::assertNotNull($node->getDocComment());
        self::assertStringContainsString('// the title', (new Standard())->prettyPrint([$node]));
        self::assertStringContainsString('// tail', (new Standard())->prettyPrint([$node]), 'the trailing Nop stays');
        self::assertSame($before, (new Standard())->prettyPrint([$node]));
        self::assertSame($node, $symbols->findMethod(self::CLS, 'show')?->node);
    }

    private function print(string $source, string $symbol): string
    {
        return $this->fingerprinter($source)->fingerprint(self::FILE, $symbol, Category::Idor, self::payload(''));
    }

    private function fingerprinter(string $source, string $routes = self::ROUTE_FILE): Fingerprinter
    {
        [$parsed, $symbols] = $this->project([self::FILE => $source, self::ROUTES => $routes]);

        return new Fingerprinter($parsed, $symbols);
    }

    /**
     * @param  array<string, string>  $files
     * @return array{ParseResult, SymbolTable}
     */
    private function project(array $files): array
    {
        $root = sys_get_temp_dir().'/ss-fp-'.bin2hex(random_bytes(6));
        $this->roots[] = $root;
        foreach ($files as $path => $code) {
            @mkdir(dirname($root.'/'.$path), 0777, true);
            file_put_contents($root.'/'.$path, $code);
        }
        $parsed = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse($root);
        self::assertSame([], $parsed->failures);

        return [$parsed, (new SymbolTableBuilder())->build($parsed)];
    }

    private static function payload(string $code): Payload
    {
        $route = new RouteEntry(['GET'], '/posts/{id}', null, new RouteAction(self::CLS, 'show'), [], [], [], null, self::ROUTES, 1);
        $node = new PathNode(self::SHOW, null, null, self::FILE, 9, 13, 0, null, null);

        return new Payload('001-get-posts-id-1', new Candidate($route, new ExecutionPath([$node], []), [], []), '', $code, 1, 1, false);
    }
}
