<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Parsing\CallGraph;

use PhpParser\Node\Expr;
use PhpParser\NodeFinder;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Config\ConfigLoader;
use TusharKhan\SemanticSec\Framework\FrameworkDetector;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Framework\Laravel\RouteAction;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\CallGraph\CallGraphBuilder;
use TusharKhan\SemanticSec\Parsing\CallGraph\ExecutionPath;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Parsing\CallGraph\TypeResolver;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ParsedFile;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\RelationResolver;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class CallGraphBuilderTest extends TestCase
{
    private const CONTROLLER = 'App\Http\Controllers\OrderController';

    private const FILES = [
        'app/Models/User.php' => '<?php namespace App\Models; class User extends \Illuminate\Foundation\Auth\User {}',
        'app/Models/Order.php' => <<<'PHP'
            <?php
            namespace App\Models;

            class Order extends \Illuminate\Database\Eloquent\Model
            {
                public function ship(): void { $this->touch(); }
            }
            PHP,
        'app/Services/Chain.php' => <<<'PHP'
            <?php
            namespace App\Services;

            class Chain
            {
                public function one(): void { $this->two(); }
                public function two(): void { $this->three(); }
                public function three(): void { $this->four(); }
                public function four(): void { }
            }
            PHP,
        'app/Services/Ping.php' => <<<'PHP'
            <?php
            namespace App\Services;

            class Ping
            {
                public function __construct(private Pong $pong) {}
                public function ping(): void { $this->pong->pong(); $this->ping(); }
            }
            PHP,
        'app/Services/Pong.php' => <<<'PHP'
            <?php
            namespace App\Services;

            class Pong
            {
                public function pong(Ping $ping): void { $ping->ping(); }
            }
            PHP,
        'app/Contracts/Notifier.php' => '<?php namespace App\Contracts; interface Notifier { public function send(): void; }',
        'app/Contracts/Payer.php' => '<?php namespace App\Contracts; interface Payer { public function pay(): void; }',
        'app/Services/MailNotifier.php' => '<?php namespace App\Services; class MailNotifier implements \App\Contracts\Notifier { public function send(): void {} }',
        'app/Services/CardPayer.php' => '<?php namespace App\Services; class CardPayer implements \App\Contracts\Payer { public function pay(): void {} }',
        'app/Services/CashPayer.php' => '<?php namespace App\Services; class CashPayer implements \App\Contracts\Payer { public function pay(): void {} }',
        'app/Services/Audit.php' => '<?php namespace App\Services; class Audit { public function log(): void {} public static function record(): void {} }',
        'app/Http/Controllers/OrderController.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            use App\Contracts\Notifier;
            use App\Contracts\Payer;
            use App\Models\Order;
            use App\Services\Audit;
            use App\Services\Chain;
            use App\Services\Checker;
            use App\Services\Ping;
            use Illuminate\Support\Facades\DB;
            use Illuminate\Support\Facades\Gate;
            use Vendor\Sdk\Client;

            class OrderController extends \Illuminate\Routing\Controller
            {
                public function chain(Chain $chain) { $chain->one(); }
                public function cycle(Ping $ping) { $ping->ping(); }
                public function facade() { Gate::authorize('x'); }
                public function vendor(Client $client) { $client->send(); }
                public function single(Notifier $notifier) { $notifier->send(); }
                public function many(Payer $payer) { $payer->pay(); }
                public function container() { app(Audit::class)->log(); resolve(Audit::class)->log(); }
                public function staticCall() { Audit::record(); }
                public function dynamic(Audit $audit, string $m) { $audit->$m(); call_user_func([$audit, 'log']); }
                public function conditional(Audit $audit, Order $order, bool $flag)
                {
                    $audit->log();
                    if ($flag) {
                        $order->ship();
                    }
                }
                public function callbacks(Order $order)
                {
                    collect([1])->each(function () use ($order) { $order->ship(); });
                    DB::transaction(fn () => Audit::record());
                }
                public function unknown($thing) { $thing->go(); }
                public function nullsafe(?Audit $audit, ?Order $order) { $order?->ship(); $order?->missing($audit->log()); }
                public function abs(\App\Services\BaseRepo $r) { $r->find(); }
                public function concrete(\App\Services\Reader $r) { $r->read(); }
                public function shared(\App\Services\BaseSvc $s) { $s->run(); }
                public function two(\App\Services\AdminSvc $x, \App\Services\UserSvc $u) { $x->run(); $u->run(); }
                public function ctor(string $s) { new \App\Services\Ctor(); new \Vendor\Sdk\Thing(); my_helper(); strlen('x'); response(); unserialize($s); }
                public function early(Checker $c, bool $f) { if ($f) { return response()->json([]); } $c->chk(); }
                public function tern(Checker $c, bool $f) { $x = $f ? $c->chk() : null; }
                public function coal(Checker $c, $v) { $x = $v ?? $c->chk(); }
                public function andd(Checker $c, bool $f) { $f && $c->chk(); }
                public function mat(Checker $c, int $f) { match ($f) { 1 => 1, 2 => $c->chk() }; }
                public function tryc(Checker $c) { try { $c->chk(); } catch (\Exception $e) {} }
                public function txearly(Checker $c) { DB::transaction(function () use ($c) { if (rand()) { return 1; } $c->chk(); }); }
                public function inner(Checker $c, bool $f) { if ($f) { $this->helper($c); } }
                private function helper(Checker $c) { $c->chk(); }
                public function vendorParent() { $this->authorize(); }
            }
            PHP,
        'app/Services/Checker.php' => '<?php namespace App\Services; class Checker { public function chk(): void {} }',
        'app/Services/BaseRepo.php' => '<?php namespace App\Services; abstract class BaseRepo { public function find(): void { $this->guard(); } protected function guard(): void {} }',
        'app/Services/OpenRepo.php' => '<?php namespace App\Services; class OpenRepo extends BaseRepo { public function find(): void {} }',
        'app/Services/Reader.php' => '<?php namespace App\Services; class Reader { public function read(): void {} }',
        'app/Services/SafeReader.php' => '<?php namespace App\Services; class SafeReader extends Reader { public function read(): void {} }',
        'app/Services/BaseSvc.php' => '<?php namespace App\Services; abstract class BaseSvc { public function run(): void { $this->hook(); } abstract protected function hook(): void; }',
        'app/Services/AdminSvc.php' => '<?php namespace App\Services; class AdminSvc extends BaseSvc { protected function hook(): void {} }',
        'app/Services/UserSvc.php' => '<?php namespace App\Services; class UserSvc extends BaseSvc { protected function hook(): void {} }',
        'app/Services/Ctor.php' => '<?php namespace App\Services; class Ctor { public function __construct() {} }',
        'app/Http/Controllers/BaseController.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            abstract class BaseController
            {
                public function index() { $this->hook(); }
                protected function hook(): void {}
            }
            PHP,
        'app/Http/Controllers/PostController.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            use App\Models\Order;

            class PostController extends BaseController
            {
                protected function hook(): void {}
                public function chained() { return Order::where('a', 1)->latest()->first(); }
            }
            PHP,
        'routes/web.php' => <<<'PHP'
            <?php
            use App\Services\Audit;
            use Illuminate\Support\Facades\Route;

            Route::get('/c', function (Audit $audit) { $audit->log(); });
            PHP,
    ];

    /** @var array<string, ParsedFile> */
    private static array $parsed = [];

    private static ?SymbolTable $symbols = null;

    public function testBenchmarkCase7ReachesDownloadServiceAtDepthOne(): void
    {
        $root = BenchmarkCorpus::root().'/laravel11-app';
        $parsed = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse($root);
        $symbols = (new SymbolTableBuilder())->build($parsed);
        $map = (new LaravelContext())->buildAuthorizationMap($parsed, $symbols, (new ConfigLoader())->load($root), (new FrameworkDetector())->detect($root));
        $route = null;
        foreach ($map->routes as $entry) {
            if ($entry->action->symbol() === 'App\Http\Controllers\Vuln\DownloadController::show') {
                $route = $entry;
            }
        }
        self::assertNotNull($route);
        $builder = new CallGraphBuilder($symbols, new TypeResolver($symbols, new RelationResolver($symbols), 'App\Models\User'), (new LaravelContext())->facadeMap(), 3);
        $path = $builder->build($route);

        self::assertSame('App\Http\Controllers\Vuln\DownloadController::show', $path->entry()->id);
        $node = self::node($path, 'App\Services\DownloadService::find');
        self::assertSame(1, $node->depth);
        self::assertSame('App\Http\Controllers\Vuln\DownloadController::show', $node->calledBy);
        self::assertFalse($node->calledFrom?->conditional);
    }

    public function testDepthLimitIsRespected(): void
    {
        $path = self::build('chain', 2);
        self::assertSame([self::CONTROLLER.'::chain', 'App\Services\Chain::one', 'App\Services\Chain::two'], self::ids($path));
        self::assertSame([0, 1, 2], array_map(static fn (PathNode $n): int => $n->depth, $path->nodes));
        self::assertCount(4, self::build('chain', 3)->nodes);
    }

    public function testCyclesTerminate(): void
    {
        $path = self::build('cycle', 5);
        self::assertSame([self::CONTROLLER.'::cycle', 'App\Services\Ping::ping', 'App\Services\Pong::pong'], self::ids($path));
    }

    public function testFacadeIsRecordedNotTraversed(): void
    {
        $path = self::build('facade');
        self::assertCount(1, $path->nodes);
        self::assertSame(["app/Http/Controllers/OrderController.php:19: [facade] \\Illuminate\\Support\\Facades\\Gate::authorize('x')"], $path->unresolved);
    }

    public function testVendorClassIsUnresolved(): void
    {
        $path = self::build('vendor');
        self::assertCount(1, $path->nodes);
        self::assertCount(1, $path->unresolved);
        self::assertStringStartsWith('app/Http/Controllers/OrderController.php:20: [not-in-project] $client->send()', $path->unresolved[0]);
        self::assertStringContainsString('Vendor\Sdk\Client', $path->unresolved[0]);
    }

    public function testInterfaceWithOneImplementationIsFollowed(): void
    {
        $path = self::build('single');
        self::assertSame([self::CONTROLLER.'::single', 'App\Services\MailNotifier::send'], self::ids($path));
        self::assertTrue($path->nodes[1]->assumed);
        self::assertSame(['app/Http/Controllers/OrderController.php:21: [assumed] $notifier->send() → App\Services\MailNotifier'], $path->unresolved);
    }

    public function testInterfaceWithTwoImplementationsListsBoth(): void
    {
        $path = self::build('many');
        self::assertCount(1, $path->nodes);
        self::assertCount(1, $path->unresolved);
        self::assertStringStartsWith('app/Http/Controllers/OrderController.php:22: [ambiguous] $payer->pay()', $path->unresolved[0]);
        self::assertStringContainsString('App\Services\CardPayer::pay, App\Services\CashPayer::pay', $path->unresolved[0]);
    }

    public function testContainerResolvedCallsAreFollowed(): void
    {
        $path = self::build('container');
        self::assertSame([self::CONTROLLER.'::container', 'App\Services\Audit::log'], self::ids($path));
        self::assertSame(['app/Http/Controllers/OrderController.php:23: [already-visited] resolve(\\App\\Services\\Audit::class)->log() → App\\Services\\Audit::log'], $path->unresolved);
    }

    public function testStaticCallOnAClassIsFollowed(): void
    {
        self::assertSame([self::CONTROLLER.'::staticCall', 'App\Services\Audit::record'], self::ids(self::build('staticCall')));
    }

    public function testDynamicCallsAreUnresolved(): void
    {
        $path = self::build('dynamic');
        self::assertCount(1, $path->nodes);
        self::assertCount(2, $path->unresolved);
        self::assertStringStartsWith('app/Http/Controllers/OrderController.php:25: [dynamic] $audit->{$m}()', $path->unresolved[0]);
        self::assertStringStartsWith("app/Http/Controllers/OrderController.php:25: [dynamic] call_user_func([\$audit, 'log'])", $path->unresolved[1]);
    }

    public function testUntypedReceiverIsUnresolved(): void
    {
        $path = self::build('unknown');
        self::assertCount(1, $path->nodes);
        self::assertStringStartsWith('app/Http/Controllers/OrderController.php:38: [unknown-type] $thing->go()', $path->unresolved[0] ?? '');
    }

    public function testClosureRouteIsTheEntry(): void
    {
        $closure = (new NodeFinder())->findFirstInstanceOf(self::parsedRoutes(), Expr\Closure::class);
        self::assertInstanceOf(Expr\Closure::class, $closure);
        $route = new RouteEntry(['GET'], '/c', null, new RouteAction(null, null, $closure), [], [], [], null, 'routes/web.php', 5);
        $path = self::builder(3)->build($route);

        self::assertSame(['closure@routes/web.php:5', 'App\Services\Audit::log'], self::ids($path));
        self::assertSame($closure, $path->entry()->closure);
        self::assertNull($path->entry()->method);
        self::assertNull($path->entry()->closureClass);
        self::assertSame(0, $path->entry()->depth);
    }

    public function testMissingActionGivesAPlaceholderEntry(): void
    {
        $route = new RouteEntry(['GET'], '/x', null, new RouteAction(self::CONTROLLER, 'nope'), [], [], [], null, 'routes/web.php', 9);
        $path = self::builder(3)->build($route);

        self::assertCount(1, $path->nodes);
        self::assertNull($path->entry()->method);
        self::assertNull($path->entry()->closure);
        self::assertSame(['routes/web.php:9: [not-found] action '.self::CONTROLLER.'::nope'], $path->unresolved);
    }

    public function testConditionalCallSiteFlag(): void
    {
        $path = self::build('conditional');
        self::assertFalse(self::node($path, 'App\Services\Audit::log')->calledFrom?->conditional);
        self::assertTrue(self::node($path, 'App\Models\Order::ship')->calledFrom?->conditional);
    }

    public function testClosureCallbacksAreConditionalExceptTransactions(): void
    {
        $path = self::build('callbacks');
        self::assertSame([self::CONTROLLER.'::callbacks', 'App\Models\Order::ship', 'App\Services\Audit::record'], self::ids($path));
        self::assertTrue(self::node($path, 'App\Models\Order::ship')->calledFrom?->conditional);
        self::assertFalse(self::node($path, 'App\Services\Audit::record')->calledFrom?->conditional);
    }

    public function testInheritedActionBindsThisToTheRouteClass(): void
    {
        $route = new RouteEntry(['GET'], '/p', null, new RouteAction('App\Http\Controllers\PostController', 'index'), [], [], [], null, 'routes/web.php', 1);
        $path = self::builder(3)->build($route);

        self::assertSame(['App\Http\Controllers\PostController::index', 'App\Http\Controllers\PostController::hook'], self::ids($path));
        self::assertSame('App\Http\Controllers\PostController', $path->entry()->closureClass);
    }

    public function testAnUnresolvedChainIsOneEntry(): void
    {
        $route = new RouteEntry(['GET'], '/p', null, new RouteAction('App\Http\Controllers\PostController', 'chained'), [], [], [], null, 'routes/web.php', 1);
        $path = self::builder(3)->build($route);

        self::assertSame(["app/Http/Controllers/PostController.php:9: [eloquent] \\App\\Models\\Order::where('a', 1)->latest()->first()"], $path->unresolved);
    }

    public function testNullsafeCallsAreConditional(): void
    {
        $path = self::build('nullsafe');
        self::assertTrue(self::node($path, 'App\Models\Order::ship')->calledFrom?->conditional);
        self::assertTrue(self::node($path, 'App\Services\Audit::log')->calledFrom?->conditional);
    }

    public function testAbstractReceiverUsesTheSoleOverride(): void
    {
        $path = self::build('abs');
        self::assertSame([self::CONTROLLER.'::abs', 'App\Services\OpenRepo::find'], self::ids($path));
        self::assertTrue($path->nodes[1]->assumed);
        self::assertFalse($path->entry()->assumed);
        self::assertContains('app/Http/Controllers/OrderController.php:40: [assumed] $r->find() → App\Services\OpenRepo', $path->unresolved);
    }

    public function testConcreteReceiverWithOverridesIsFollowedAndFlagged(): void
    {
        $path = self::build('concrete');
        self::assertSame([self::CONTROLLER.'::concrete', 'App\Services\Reader::read'], self::ids($path));
        self::assertFalse($path->nodes[1]->assumed);
        self::assertSame(['app/Http/Controllers/OrderController.php:41: [may-be-overridden] $r->read() → App\Services\SafeReader'], $path->unresolved);
    }

    public function testSharedInheritedMethodLeavesThisDispatchAmbiguous(): void
    {
        $path = self::build('shared');
        self::assertSame([self::CONTROLLER.'::shared', 'App\Services\BaseSvc::run'], self::ids($path));
        self::assertContains('app/Services/BaseSvc.php:1: [ambiguous] $this->hook() → App\Services\AdminSvc::hook, App\Services\UserSvc::hook', $path->unresolved);
    }

    public function testEachSubclassBindingIsItsOwnNode(): void
    {
        $path = self::build('two');
        self::assertSame([self::CONTROLLER.'::two', 'App\Services\AdminSvc::run', 'App\Services\UserSvc::run', 'App\Services\AdminSvc::hook', 'App\Services\UserSvc::hook'], self::ids($path));
        self::assertSame('App\Services\BaseSvc::run', $path->nodes[1]->method?->id());
        self::assertSame('App\Services\AdminSvc', $path->nodes[1]->closureClass);
    }

    public function testConstructorsFunctionsAndSinksAreRecorded(): void
    {
        $path = self::build('ctor');
        self::assertSame([self::CONTROLLER.'::ctor', 'App\Services\Ctor::__construct'], self::ids($path));
        $prefix = 'app/Http/Controllers/OrderController.php:44: ';
        self::assertSame([
            $prefix.'[not-in-project] new \Vendor\Sdk\Thing() → Vendor\Sdk\Thing::__construct',
            $prefix.'[function] my_helper()',
            $prefix.'[sink] unserialize($s)',
        ], $path->unresolved);
    }

    public function testConditionalShapes(): void
    {
        foreach (['early', 'tern', 'coal', 'andd', 'mat', 'tryc', 'txearly'] as $method) {
            self::assertTrue(self::node(self::build($method), 'App\Services\Checker::chk')->calledFrom?->conditional, $method);
        }
    }

    public function testConditionalityIsPerCallSiteNotTransitive(): void
    {
        $path = self::build('inner');
        self::assertTrue(self::node($path, self::CONTROLLER.'::helper')->calledFrom?->conditional);
        $chk = self::node($path, 'App\Services\Checker::chk');
        self::assertSame(self::CONTROLLER.'::helper', $chk->calledBy);
        self::assertFalse($chk->calledFrom?->conditional);
    }

    public function testMethodMissingBelowAVendorParentIsNotInProject(): void
    {
        $path = self::build('vendorParent');
        self::assertSame(['app/Http/Controllers/OrderController.php:54: [not-in-project] $this->authorize() → '.self::CONTROLLER.'::authorize via Illuminate\Routing\Controller'], $path->unresolved);
    }

    public function testDepthLimitIsRecordedPerNode(): void
    {
        self::assertSame(['app/Services/Chain.php:7: [depth-limit] App\Services\Chain::two'], self::build('chain', 2)->unresolved);
    }

    private static function build(string $method, int $maxDepth = 3): ExecutionPath
    {
        $route = new RouteEntry(['GET'], '/'.$method, null, new RouteAction(self::CONTROLLER, $method), [], [], [], null, 'routes/web.php', 1);

        return self::builder($maxDepth)->build($route);
    }

    private static function builder(int $maxDepth): CallGraphBuilder
    {
        $symbols = self::symbols();

        return new CallGraphBuilder($symbols, new TypeResolver($symbols, new RelationResolver($symbols), 'App\Models\User'), (new LaravelContext())->facadeMap(), $maxDepth);
    }

    /** @return list<string> */
    private static function ids(ExecutionPath $path): array
    {
        return array_map(static fn (PathNode $n): string => $n->id, $path->nodes);
    }

    private static function node(ExecutionPath $path, string $id): PathNode
    {
        foreach ($path->nodes as $node) {
            if ($node->id === $id) {
                return $node;
            }
        }
        self::fail($id.' not on the path: '.implode(', ', self::ids($path)));
    }

    /** @return array<\PhpParser\Node\Stmt> */
    private static function parsedRoutes(): array
    {
        self::symbols();

        return self::$parsed['routes/web.php']->ast;
    }

    private static function symbols(): SymbolTable
    {
        if (self::$symbols === null) {
            $files = [];
            foreach (self::FILES as $path => $code) {
                $files[] = self::$parsed[$path] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
            }
            self::$symbols = (new SymbolTableBuilder())->build(new ParseResult($files, []));
        }

        return self::$symbols;
    }
}
