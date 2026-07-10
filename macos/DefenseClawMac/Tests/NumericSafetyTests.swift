// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

import Foundation

@main
struct NumericSafetyTests {
    static func main() {
        truncatesOnlyRepresentableFiniteIntegers()
        normalizesConfidenceWithinFiniteUnitBounds()
        convertsConfidenceToPercentWithoutTrapping()
        rejectsNonFiniteTimestamps()
        formatsUnrepresentableCacheAgesSafely()
        preservesNormalCacheAgeLabels()
        print("Numeric safety tests passed")
    }

    private static func truncatesOnlyRepresentableFiniteIntegers() {
        expect(DCSafeNumbers.intTruncating(42.9) == 42, "finite integer truncation")
        expect(DCSafeNumbers.intTruncating(-42.9) == -42, "negative integer truncation")
        expect(DCSafeNumbers.intTruncating(1e22) == nil, "huge positive integer is rejected")
        expect(DCSafeNumbers.intTruncating(-1e22) == nil, "huge negative integer is rejected")
        expect(DCSafeNumbers.intTruncating(Double.infinity) == nil, "infinite integer is rejected")
        expect(DCSafeNumbers.intTruncating(Double.nan) == nil, "NaN integer is rejected")
    }

    private static func normalizesConfidenceWithinFiniteUnitBounds() {
        expect(AIConfidence.normalize(0.75) == 0.75, "fraction confidence")
        expect(AIConfidence.normalize(75) == 0.75, "percent confidence")
        expect(AIConfidence.normalize(150.0) == 1, "oversized confidence clamps high")
        expect(AIConfidence.normalize(-10.0) == 0, "negative confidence clamps low")
        expect(AIConfidence.normalize(Double.infinity) == 0, "positive infinity is rejected")
        expect(AIConfidence.normalize(-Double.infinity) == 0, "negative infinity is rejected")
        expect(AIConfidence.normalize(Double.nan) == 0, "NaN is rejected")
    }

    private static func convertsConfidenceToPercentWithoutTrapping() {
        expect(AIConfidence.percent(Double.infinity) == 0, "infinite confidence percent")
        expect(AIConfidence.percent(Double.nan) == 0, "NaN confidence percent")
        expect(AIConfidence.percent(-1e22) == 0, "huge negative confidence percent")
        expect(AIConfidence.percent(1e22) == 100, "huge positive confidence percent")
        expect(AIConfidence.percent(0.559) == 55, "truncated confidence percent")
        expect(
            AIConfidence.percent(0.555, roundingRule: .toNearestOrAwayFromZero) == 56,
            "rounded confidence percent"
        )
        expect(
            AIDiscoveryGrouping.formatConfidence(score: Double.infinity, band: "").isEmpty,
            "invalid unbanded confidence is omitted"
        )
        expect(
            AIDiscoveryGrouping.formatConfidence(score: 0.756, band: "high") == "high (76%)",
            "normal formatted confidence"
        )
    }

    private static func rejectsNonFiniteTimestamps() {
        expect(DCDates.parse(Double.infinity) == nil, "positive infinite timestamp")
        expect(DCDates.parse(-Double.infinity) == nil, "negative infinite timestamp")
        expect(DCDates.parse(Double.nan) == nil, "NaN timestamp")
        expect(DCDates.parse(1_700_000_000.0) != nil, "finite seconds timestamp")
        expect(DCDates.parse(1_700_000_000_000.0) != nil, "finite milliseconds timestamp")
    }

    private static func formatsUnrepresentableCacheAgesSafely() {
        let now = Date(timeIntervalSince1970: 0)
        var cache = DoctorCache()

        cache.capturedAt = Date(timeIntervalSince1970: 1e22)
        expect(cache.ageLabel(now: now) == "never", "huge future cache age")

        cache.capturedAt = Date(timeIntervalSince1970: -1e22)
        expect(cache.ageLabel(now: now) == "never", "huge past cache age")

        cache.capturedAt = Date(timeIntervalSince1970: Double.infinity)
        expect(cache.ageLabel(now: now) == "never", "infinite cache age")
    }

    private static func preservesNormalCacheAgeLabels() {
        let now = Date(timeIntervalSince1970: 100_000)
        var cache = DoctorCache()

        expect(cache.ageLabel(now: now) == "never", "missing cache timestamp")

        cache.capturedAt = now.addingTimeInterval(0.5)
        expect(cache.ageLabel(now: now) == "just now", "sub-second future skew")

        cache.capturedAt = now.addingTimeInterval(-59.9)
        expect(cache.ageLabel(now: now) == "59s ago", "seconds cache age")

        cache.capturedAt = now.addingTimeInterval(-3_601)
        expect(cache.ageLabel(now: now) == "1h ago", "hours cache age")
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            fputs("FAILED: \(label)\n", stderr)
            exit(1)
        }
    }
}
