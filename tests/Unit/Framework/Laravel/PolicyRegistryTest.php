<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\Laravel\ConstantEvaluator;
use TusharKhan\SemanticSec\Framework\Laravel\PolicyRegistry;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class PolicyRegistryTest extends TestCase
{
    /** @var list<string> */
    private array $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $dir) {
            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST) as $f) {
                $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
            }
            rmdir($dir);
        }
    }

    /** @return array{0: PolicyRegistry, 1: list<string>} */
    private function load(string $root): array
    {
        $parsed = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse($root);

        return PolicyRegistry::fromProject((new SymbolTableBuilder())->build($parsed), new ConstantEvaluator());
    }

    /** @param array<string, string> $files */
    private function project(array $files): string
    {
        $dir = sys_get_temp_dir().'/ss-pr-'.bin2hex(random_bytes(4));
        mkdir($dir);
        $this->dirs[] = $dir;
        foreach ($files as $path => $code) {
            @mkdir(dirname($dir.'/'.$path), 0777, true);
            file_put_contents($dir.'/'.$path, $code);
        }

        return $dir;
    }

    public function testGatePolicyRegistration(): void
    {
        [$registry, $warnings] = $this->load(BenchmarkCorpus::root().'/laravel11-app');
        self::assertSame('App\\Policies\\ReplyOwnershipPolicy', $registry->policyFor('App\\Models\\Reply'));
        self::assertNotNull($registry->abilityHolder('App\\Policies\\ReplyOwnershipPolicy', 'delete'));
        self::assertFalse($registry->isTrivial('App\\Policies\\ReplyOwnershipPolicy', 'delete'));
        self::assertSame([], $warnings);
    }

    public function testTrivialPolicy(): void
    {
        [$registry] = $this->load(BenchmarkCorpus::root().'/laravel11-app');
        self::assertSame('App\\Policies\\CommentPolicy', $registry->policyFor('App\\Models\\Comment'));
        self::assertTrue($registry->isTrivial('App\\Policies\\CommentPolicy', 'delete'));
        self::assertSame('delete', $registry->abilityHolder('App\\Policies\\CommentPolicy', 'delete')?->name);
    }

    public function testPoliciesProperty(): void
    {
        [$registry] = $this->load(BenchmarkCorpus::root().'/laravel10-app');
        self::assertSame('App\\Policies\\NoteAccessPolicy', $registry->policyFor('App\\Models\\Note'));
        self::assertSame('App\\Policies\\ReportPolicy', $registry->policyFor('App\\Models\\Report'));
    }

    public function testAutoDiscovery(): void
    {
        [$registry] = $this->load(BenchmarkCorpus::root().'/laravel11-app');
        self::assertSame('App\\Policies\\InvoicePolicy', $registry->policyFor('App\\Models\\Invoice'));
    }

    public function testAutoDiscoveryWithoutModelsNamespace(): void
    {
        $root = $this->project(['app/P.php' => "<?php\nnamespace App\\Policies;\nclass XPolicy {}\n"]);
        [$registry] = $this->load($root);
        self::assertSame('App\\Policies\\XPolicy', $registry->policyFor('App\\X'));
        self::assertNull($registry->policyFor('App\\Models\\Y'));
    }

    public function testMissingPolicyMethodIsNotTrivial(): void
    {
        [$registry] = $this->load(BenchmarkCorpus::root().'/laravel11-app');
        self::assertFalse($registry->isTrivial('App\\Policies\\CommentPolicy', 'noSuchAbility'));
        self::assertNull($registry->abilityHolder('App\\Policies\\CommentPolicy', 'noSuchAbility'));
    }

    public function testNoPolicyReturnsNull(): void
    {
        [$registry] = $this->load(BenchmarkCorpus::root().'/laravel11-app');
        self::assertNull($registry->policyFor('App\\Models\\Nothing'));
    }

    public function testRegistrationWinsAndDuplicatesWarn(): void
    {
        $root = $this->project(['app/S.php' => <<<'PHP'
<?php
namespace App\Providers;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Gate;
class S extends ServiceProvider {
    public function boot(): void {
        Gate::policy(\App\Models\X::class, \App\Policies\A::class);
        Gate::policy(\App\Models\X::class, \App\Policies\B::class);
        Gate::policy($dyn, \App\Policies\B::class);
    }
}
PHP, 'app/Pol.php' => "<?php\nnamespace App\\Policies;\nclass A {}\nclass B {}\nclass XPolicy {}\n"]);
        [$registry, $warnings] = $this->load($root);
        self::assertSame('App\\Policies\\A', $registry->policyFor('App\\Models\\X'));
        self::assertCount(2, $warnings);
        self::assertStringContainsString('model App\\Models\\X has multiple policies', $warnings[0]);
        self::assertStringContainsString('Gate::policy could not be resolved', $warnings[1]);
    }

    private function policyRegistry(string $policyBody): PolicyRegistry
    {
        $root = $this->project(['app/P.php' => "<?php\nnamespace App\\Policies;\nuse Illuminate\\Auth\\Access\\Response;\n".$policyBody]);

        return $this->load($root)[0];
    }

    public function testTrivialVariants(): void
    {
        $r = $this->policyRegistry(<<<'PHP'
class P {
    public function a($u) { return TRUE; }
    public function b($u) { return Response::allow(); }
    public function c($u) { // return true;
    }
    public function d($u) { return $u !== null; }
    public function e($u) { return Response::deny(); }
}
PHP);
        self::assertTrue($r->isTrivial('App\\Policies\\P', 'a'));
        self::assertTrue($r->isTrivial('App\\Policies\\P', 'B'));
        self::assertFalse($r->isTrivial('App\\Policies\\P', 'c'));
        self::assertFalse($r->isTrivial('App\\Policies\\P', 'd'));
        self::assertFalse($r->isTrivial('App\\Policies\\P', 'e'));
    }

    public function testBeforeMakesEveryAbilityTrivial(): void
    {
        $r = $this->policyRegistry(<<<'PHP'
class Base { public function before($u) { return Response::allow(); } }
class P extends Base { public function d($u) { return $u !== null; } }
class Q { public function before($u) { return true; } }
class R { public function before($u) { return null; } public function d($u) { return false; } }
PHP);
        self::assertTrue($r->isTrivial('App\\Policies\\P', 'd'));
        self::assertTrue($r->isTrivial('App\\Policies\\Q', 'missing'));
        self::assertFalse($r->isTrivial('App\\Policies\\R', 'd'));
    }

    public function testIdenticalDuplicateRegistrationDoesNotWarn(): void
    {
        $root = $this->project(['app/S.php' => <<<'PHP'
<?php
namespace App\Providers;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Gate;
class S extends ServiceProvider {
    public function boot(): void {
        Gate::policy(\App\Models\X::class, \App\Policies\A::class);
        Gate::policy(\App\Models\X::class, \App\Policies\A::class);
    }
}
PHP]);
        self::assertSame([], $this->load($root)[1]);
    }

    public function testUnresolvablePoliciesEntryWarns(): void
    {
        $root = $this->project(['app/A.php' => <<<'PHP'
<?php
namespace App\Providers;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider;
class A extends AuthServiceProvider {
    protected $policies = [ \App\Models\X::class => \App\Policies\P::class, $dyn => \App\Policies\P::class ];
}
PHP]);
        [$registry, $warnings] = $this->load($root);
        self::assertSame('App\\Policies\\P', $registry->policyFor('App\\Models\\X'));
        self::assertCount(1, $warnings);
        self::assertStringContainsString('policy mapping could not be resolved', $warnings[0]);
    }

    public function testDiscoveryOrderMirrorsLaravel(): void
    {
        $root = $this->project(['app/P.php' => "<?php\nnamespace App\\Policies;\nclass XPolicy {}\n", 'app/Q.php' => "<?php\nnamespace App\\Models\\Policies;\nclass XPolicy {}\n", 'app/R.php' => "<?php\nnamespace App\\Policies\\Sub;\nclass YPolicy {}\n"]);
        [$registry] = $this->load($root);
        self::assertSame('App\\Models\\Policies\\XPolicy', $registry->policyFor('App\\Models\\X'));
        self::assertSame('App\\Policies\\Sub\\YPolicy', $registry->policyFor('App\\Models\\Sub\\Y'));
    }

    public function testUsePolicyAttribute(): void
    {
        $root = $this->project(['app/M.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Attributes\\UsePolicy;\n#[UsePolicy(\\App\\Policies\\Custom::class)]\nclass M {}\n#[UsePolicy(\$x)]\nclass N {}\n"]);
        [$registry, $warnings] = $this->load($root);
        self::assertSame('App\\Policies\\Custom', $registry->policyFor('App\\Models\\M'));
        self::assertCount(1, $warnings);
    }
}
