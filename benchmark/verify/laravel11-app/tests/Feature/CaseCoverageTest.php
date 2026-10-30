<?php

namespace Tests\Feature;

use Illuminate\Support\Str;
use ReflectionClass;
use Tests\TestCase;

class CaseCoverageTest extends TestCase
{
    public const APP = 'laravel11-app';

    /** @return list<string> */
    private function testMethods(): array
    {
        $methods = [];
        foreach (glob(__DIR__.'/*Test.php') ?: [] as $file) {
            $class = 'Tests\\Feature\\'.basename($file, '.php');
            foreach ((new ReflectionClass($class))->getMethods() as $method) {
                if ($method->isPublic() && $method->getDeclaringClass()->getName() === $class) {
                    $methods[] = $method->getName();
                }
            }
        }

        return $methods;
    }

    public function testEveryExpectedCaseAndPublicRouteHasATest(): void
    {
        $path = getenv('SEMANTIC_SEC_EXPECTED_JSON');
        if ($path === false || $path === '') {
            $this->markTestSkipped('SEMANTIC_SEC_EXPECTED_JSON is not set; run.sh sets it.');
        }
        $expected = json_decode((string) file_get_contents($path), true);
        $this->assertIsArray($expected, 'expected JSON must decode');

        $have = $this->testMethods();
        $want = [];
        foreach ($expected['cases'] ?? [] as $case) {
            if (($case['app'] ?? null) === static::APP) {
                $studly = Str::studly($case['id']);
                array_push($want, "test{$studly}Vulnerable", "test{$studly}Safe");
            }
        }
        foreach ($expected['public_routes'] ?? [] as $public) {
            if (($public['app'] ?? null) === static::APP) {
                $want[] = 'testPublicRoute'.Str::studly(Str::afterLast($public['symbol'], '::'));
            }
        }

        $this->assertNotEmpty($want, 'no expected cases for '.static::APP);
        $this->assertSame([], array_values(array_diff($want, $have)), 'expected tests are missing');
    }
}
